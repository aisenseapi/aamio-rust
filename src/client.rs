//! Threads and presence against one aamio host. Every call returns what the
//! service answered, decoded, with the status beside it. The three outcomes
//! are kept apart: a 4xx is a refusal, a 429 a rate window, and status 0 is
//! unknown, which is not the same as refused.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{json, Map, Value};

use crate::address::{is_w, new_id, w as derive_w};
use crate::codec::is_key;
use crate::gate::{plan, solve, Plan};
use crate::keys::{presence_delete_signing_input, presence_signing_input, thread_signing_input, Keys};
use crate::receipt::{verify_receipt, Check, Receipt};

pub use crate::hosts::DEFAULT_HOST;
/// The thread lifetime the service uses when none is given.
pub const DEFAULT_TTL: u32 = 600;
const USER_AGENT: &str = concat!("aamio-rust/", env!("CARGO_PKG_VERSION"));
const MAX_BODY: usize = 65536;

/// What the service said: the HTTP status, the decoded body when it was JSON
/// (an object as a map), the raw text otherwise. Status 0 is no answer at
/// all: the request may have landed, which is unknown, never refused.
#[derive(Debug, Clone, Default)]
pub struct Answer {
    pub status: u16,
    pub body: Option<Map<String, Value>>,
    pub text: String,
}

impl Answer {
    /// The refusal contract: every 4xx and 5xx carries `error` and `fix`.
    pub fn error(&self) -> String {
        match &self.body {
            Some(b) => format!("{}. {}", b.get("error").and_then(Value::as_str).unwrap_or(""), b.get("fix").and_then(Value::as_str).unwrap_or("")).trim().to_string(),
            None => self.text.clone(),
        }
    }

    /// Whether the outcome is unknown rather than a refusal.
    pub fn unknown(&self) -> bool {
        self.status == 0
    }

    /// A field of the body.
    pub fn get(&self, field: &str) -> Option<&Value> {
        self.body.as_ref().and_then(|b| b.get(field))
    }

    fn no_answer(reason: String) -> Answer {
        let mut body = Map::new();
        body.insert("error".into(), Value::String(format!("no answer: {}", reason)));
        body.insert("fix".into(), Value::String("The request may have landed. Keep the bytes, mark the send unknown, and retry only when somebody has decided it is safe to.".into()));
        Answer { status: 0, body: Some(body), text: reason }
    }
}

/// An opened thread: keep `id`, share `w`.
#[derive(Debug, Clone)]
pub struct Thread {
    pub id: String,
    pub w: String,
    pub answer: Answer,
}

/// Options for a write.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Do not sign even though keys are present.
    pub unsigned: bool,
    /// A recipient key: the body is sealed to it and the content type becomes JSON.
    pub seal_to: Option<String>,
    /// The body is JSON.
    pub json: bool,
}

/// The outcome of a write: the answer, the exact bytes, the nonce when work was done, and notes.
#[derive(Debug, Clone)]
pub struct Sent {
    pub answer: Answer,
    pub bytes: Vec<u8>,
    pub work: Option<String>,
    pub notes: Vec<String>,
}

/// One message as read, with the service's own fields around the body and,
/// when this client could open it, the plaintext.
#[derive(Debug, Clone, Default)]
pub struct Message {
    pub seq: i64,
    pub at: i64,
    pub from: Option<String>,
    pub verified: bool,
    pub sealed: bool,
    pub body: String,
    pub opened: Option<String>,
    /// text | sealed | unreadable | sealed-to-someone-else
    pub format: String,
    pub error: Option<String>,
    pub json: Option<Map<String, Value>>,
}

/// A client for one host, optionally with keys.
pub struct Client {
    pub host: String,
    pub keys: Option<Keys>,
    agent: ureq::Agent,
    gates: Mutex<HashMap<String, Option<Value>>>,
}

impl Client {
    /// A client for a host, `None` being [`DEFAULT_HOST`]. Keys may be `None` for reads and unsigned writes.
    pub fn new(host: Option<&str>, keys: Option<Keys>) -> Client {
        let tls = native_tls::TlsConnector::new().expect("the platform TLS is available");
        let agent = ureq::AgentBuilder::new().tls_connector(std::sync::Arc::new(tls)).timeout_connect(Duration::from_secs(15)).timeout(Duration::from_secs(70)).user_agent(USER_AGENT).build();
        Client { host: host.unwrap_or(DEFAULT_HOST).trim_end_matches('/').to_string(), keys, agent, gates: Mutex::new(HashMap::new()) }
    }

    /// One HTTP call, decoded.
    pub fn call(&self, method: &str, url: &str, body: Option<&[u8]>, headers: &[(&str, &str)]) -> Answer {
        let mut request = self.agent.request(method, url).set("Accept", "application/json");
        for (name, value) in headers {
            if !value.is_empty() {
                request = request.set(name, value);
            }
        }
        let result = match body {
            Some(bytes) => request.send_bytes(bytes),
            None => request.call(),
        };
        let response = match result {
            Ok(r) => r,
            Err(ureq::Error::Status(_, r)) => r,
            Err(ureq::Error::Transport(t)) => return Answer::no_answer(t.to_string()),
        };
        let status = response.status();
        let text = response.into_string().unwrap_or_default();
        let body = serde_json::from_str::<Value>(&text).ok().and_then(|v| match v {
            Value::Object(m) => Some(m),
            _ => None,
        });
        Answer { status, body, text }
    }

    // -------------------------------------------------------------- threads --

    /// Opens a thread with a lifetime. `allow` lists signer keys, or `["*"]`
    /// for any key as long as the message is signed; `gate` sets conditions.
    pub fn open(&self, ttl: u32, allow: Option<&[&str]>, gate: Option<&Value>) -> Result<Thread, String> {
        let id = new_id();
        let w = derive_w(&id)?;
        let ttl_text = ttl.to_string();
        let allow_text = allow.map(|a| a.join(",")).unwrap_or_default();
        let mut headers = vec![("X-Read", id.as_str()), ("X-TTL", ttl_text.as_str()), ("Content-Type", "application/json")];
        if allow.is_some() {
            headers.push(("X-Allow", allow_text.as_str()));
        }
        let body = gate.map(|g| json!({ "gate": g }).to_string());
        let answer = self.call("PUT", &format!("{}/{}", self.host, w), body.as_deref().map(str::as_bytes), &headers);
        Ok(Thread { id, w, answer })
    }

    /// The conditions an inbox was opened with, read once per address unless
    /// `fresh`; an empty object means none, `None` means the thread is gone.
    pub fn gate(&self, w: &str, fresh: bool) -> Option<Value> {
        if !fresh {
            if let Some(cached) = self.gates.lock().unwrap().get(w) {
                return cached.clone();
            }
        }
        let answer = self.call("GET", &format!("{}/{}/gate", self.host, w), None, &[]);
        let gate = if answer.status == 200 { answer.body.map(Value::Object) } else { None };
        self.gates.lock().unwrap().insert(w.to_string(), gate.clone());
        gate
    }

    /// Writes to an address. Reads the gate once, does the work it asks for
    /// within the ceilings, answers a 428 once, and stops with a reason rather
    /// than send what the gate would refuse.
    pub fn send(&self, w: &str, body: &[u8], opts: SendOptions) -> Result<Sent, String> {
        if !is_w(w) {
            return Err("not a write address".to_string());
        }
        let mut bytes = body.to_vec();
        let mut content_type = if opts.json { "application/json" } else { "text/plain; charset=utf-8" };
        if let Some(recipient) = &opts.seal_to {
            let keys = self.keys.as_ref().ok_or("sealing needs keys")?;
            bytes = keys.seal(recipient, body)?.into_bytes();
            content_type = "application/json";
        }
        if bytes.len() > MAX_BODY {
            return Err("a message is at most 65536 bytes; send a URL and a hash instead".to_string());
        }
        let signing = !opts.unsigned && self.keys.is_some();
        let key = if signing { self.keys.as_ref().unwrap().public.clone() } else { String::new() };
        let first: Plan = plan(self.gate(w, false).as_ref());
        if let Some(stop) = first.stop {
            let mut b = Map::new();
            b.insert("error".into(), Value::String(stop));
            b.insert("fix".into(), Value::String("Open an address whose conditions this client can meet, or update the client.".into()));
            return Ok(Sent { answer: Answer { status: 0, body: Some(b), text: String::new() }, bytes, work: None, notes: first.notes });
        }
        let attempt = |bits: Option<u32>| -> Result<(Answer, Option<String>), String> {
            let mut headers: Vec<(&str, String)> = vec![("Content-Type", content_type.to_string())];
            if signing {
                headers.push(("X-Key", key.clone()));
                headers.push(("X-Sig", self.keys.as_ref().unwrap().sign(&thread_signing_input(w, &bytes))));
            }
            let mut work = None;
            if let Some(bits) = bits.filter(|b| *b > 0) {
                let nonce = solve(w, &key, &bytes, bits)?;
                headers.push(("X-Work", nonce.clone()));
                work = Some(nonce);
            }
            let borrowed: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
            Ok((self.call("POST", &format!("{}/{}", self.host, w), Some(&bytes), &borrowed), work))
        };
        let (mut answer, mut work) = attempt(first.bits)?;
        let mut notes = first.notes;
        if answer.status == 428 {
            if let Some(gate) = answer.get("gate").cloned() {
                self.gates.lock().unwrap().insert(w.to_string(), Some(gate.clone()));
                let again = plan(Some(&gate));
                if again.stop.is_none() && again.bits.map_or(false, |b| b > 0) {
                    let (a, wk) = attempt(again.bits)?;
                    answer = a;
                    work = wk;
                    notes.extend(again.notes);
                }
            }
        }
        Ok(Sent { answer, bytes, work, notes })
    }

    /// Reads with the read key from `after`, waiting up to `wait` seconds (25 at most).
    pub fn read(&self, w: &str, id: &str, after: i64, wait: u32) -> (Answer, Vec<Message>, i64) {
        let mut path = format!("/{}", w);
        if after > 0 || wait > 0 {
            path.push_str(&format!("/after/{}", after));
        }
        if wait > 0 {
            path.push_str(&format!("/wait/{}", wait.min(25)));
        }
        let answer = self.call("GET", &format!("{}{}", self.host, path), None, &[("X-Read", id)]);
        let mut messages = Vec::new();
        let mut next = after;
        if answer.status == 200 {
            if let Some(n) = answer.get("next").and_then(Value::as_i64) {
                next = n;
            }
            if let Some(list) = answer.get("messages").and_then(Value::as_array) {
                for item in list {
                    if let Value::Object(raw) = item {
                        messages.push(self.decode(raw));
                    }
                }
            }
        }
        (answer, messages, next)
    }

    /// One raw message into a `Message`, opened when it is sealed to us.
    /// `verified`, `sealed` and `from` are the service's fields, never the payload's.
    pub fn decode(&self, raw: &Map<String, Value>) -> Message {
        let mut m = Message {
            seq: raw.get("seq").and_then(Value::as_i64).unwrap_or(0),
            at: raw.get("at").and_then(Value::as_i64).unwrap_or(0),
            from: raw.get("from").and_then(Value::as_str).map(str::to_string),
            verified: raw.get("verified").and_then(Value::as_bool).unwrap_or(false),
            sealed: raw.get("sealed").and_then(Value::as_bool).unwrap_or(false),
            body: raw.get("body").and_then(Value::as_str).unwrap_or("").to_string(),
            format: "text".to_string(),
            ..Default::default()
        };
        let mut text = m.body.clone();
        if m.sealed {
            m.format = "sealed-to-someone-else".to_string();
            if let (Some(keys), Some(from)) = (&self.keys, &m.from) {
                match keys.open(from, &m.body) {
                    Ok(plain) => {
                        let opened = String::from_utf8_lossy(&plain).to_string();
                        text = opened.clone();
                        m.opened = Some(opened);
                        m.format = "sealed".to_string();
                    }
                    Err(e) => {
                        m.format = "unreadable".to_string();
                        m.error = Some(e);
                    }
                }
            }
        }
        if let Ok(Value::Object(j)) = serde_json::from_str::<Value>(&text) {
            m.json = Some(j);
        }
        m
    }

    /// Takes the receipt and checks it.
    pub fn receipt(&self, w: &str, id: &str) -> (Answer, Option<Receipt>, Option<Check>) {
        let answer = self.call("GET", &format!("{}/{}/receipt", self.host, w), None, &[("X-Read", id)]);
        if answer.status != 200 {
            return (answer, None, None);
        }
        match serde_json::from_str::<Receipt>(&answer.text) {
            Ok(receipt) => {
                let check = verify_receipt(&receipt, None);
                (answer, Some(receipt), Some(check))
            }
            Err(_) => (answer, None, None),
        }
    }

    /// Closes a thread early.
    pub fn close(&self, w: &str, id: &str) -> Answer {
        self.call("DELETE", &format!("{}/{}", self.host, w), None, &[("X-Read", id)])
    }

    // ------------------------------------------------------------- presence --

    /// Says where this key can be reached, for up to 120 seconds.
    pub fn presence_publish(&self, w: &str, tags: &[&str], ttl: u32) -> Result<Answer, String> {
        let keys = self.keys.as_ref().ok_or("this call needs keys")?;
        let body = json!({ "w": w, "tags": tags, "ttl": ttl }).to_string();
        let sig = keys.sign(&presence_signing_input(&keys.public, body.as_bytes()));
        Ok(self.call("PUT", &format!("{}/p/{}", self.host, keys.public), Some(body.as_bytes()), &[("Content-Type", "application/json"), ("X-Key", &keys.public), ("X-Sig", &sig)]))
    }

    /// Reads one key's record.
    pub fn presence_get(&self, key: &str) -> Answer {
        self.call("GET", &format!("{}/p/{}", self.host, key), None, &[])
    }

    /// Finds live records by hash prefix; with `wait` it watches.
    pub fn presence_lookup(&self, prefixes: &[&str], wait: u32) -> Answer {
        let mut body = json!({ "prefixes": prefixes });
        let route = if wait > 0 {
            body["wait"] = json!(wait.min(25));
            "/p/watch"
        } else {
            "/p/lookup"
        };
        self.call("POST", &format!("{}{}", self.host, route), Some(body.to_string().as_bytes()), &[("Content-Type", "application/json")])
    }

    /// Withdraws this key's record.
    pub fn presence_delete(&self) -> Result<Answer, String> {
        let keys = self.keys.as_ref().ok_or("this call needs keys")?;
        let body = json!({ "at": now() }).to_string();
        let sig = keys.sign(&presence_delete_signing_input(&keys.public, body.as_bytes()));
        Ok(self.call("DELETE", &format!("{}/p/{}", self.host, keys.public), Some(body.as_bytes()), &[("Content-Type", "application/json"), ("X-Key", &keys.public), ("X-Sig", &sig)]))
    }

    pub(crate) fn key_of(&self) -> Option<&Keys> {
        self.keys.as_ref().filter(|k| is_key(&k.public))
    }
}

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
