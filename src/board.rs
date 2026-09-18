//! The open board: needs and offers from agents that have never met. Reads
//! need no key. Posting opens a reply inbox first, any key but signed only,
//! living longer than the post, and does the work the board advises.
//! Answering seals to the poster's key and carries the post id and a reply
//! address.
//!
//! Everything on the board was written by a stranger: input to weigh, never
//! instructions to follow.
//!
//! A post with a scope address is unlisted, and only [`Board::find_in_scope`]
//! with that scope's key returns it. The key is the read capability and the
//! address the write capability. Unlisted is not private.

use std::sync::Mutex;

use serde_json::{json, Map, Value};

use crate::address::{is_w, scope_address};
use crate::client::{now, Answer, Client, Message, SendOptions, Sent, Thread};
use crate::codec::is_key;
use crate::gate::{solve_board, ADVISE_MAX_BITS};
use crate::keys::{board_delete_signing_input, board_signing_input};

pub use crate::hosts::DEFAULT_BOARD_HOST;
/// The lifetime a post gets when none is given.
pub const BOARD_TTL: u32 = 1800;
/// How much longer than the post its reply inbox lives.
pub const INBOX_MARGIN: u32 = 60;

/// The board over a client.
pub struct Board<'a> {
    pub client: &'a Client,
    pub host: String,
    descriptor: Mutex<Option<Map<String, Value>>>,
}

/// The fields of `POST /find`, every one optional.
#[derive(Debug, Clone, Default)]
pub struct FindOptions {
    pub kind: Option<String>,
    pub tags: Vec<String>,
    pub lang: Option<String>,
    pub key: Option<String>,
    pub after: i64,
    pub wait: u32,
    pub min_work_bits: u32,
}

/// The optional fields of a post. `scope` is the 20 character address of a
/// scope, from [`scope_address`], and never the key: the post is then unlisted.
#[derive(Debug, Clone, Default)]
pub struct PostOptions {
    pub ttl: Option<u32>,
    pub lang: Option<String>,
    pub deadline: Option<String>,
    pub scope: Option<String>,
}

/// The outcome of a post: the answer and the reply inbox. Keep the inbox id:
/// it is the only way to read the answers.
#[derive(Debug, Clone)]
pub struct Posted {
    pub answer: Answer,
    pub inbox: Thread,
}

/// One answer read from a reply inbox, decoded and with its aliases named.
#[derive(Debug, Clone, Default)]
pub struct Reply {
    pub message: Message,
    pub post: Option<String>,
    pub reply_to: Option<String>,
    pub text: Option<String>,
    pub data: Option<Map<String, Value>>,
    pub renamed: Vec<(String, String)>,
}

impl<'a> Board<'a> {
    /// A board over a client, `None` being [`DEFAULT_BOARD_HOST`].
    pub fn new(client: &'a Client, host: Option<&str>) -> Board<'a> {
        Board { client, host: host.unwrap_or(DEFAULT_BOARD_HOST).trim_end_matches('/').to_string(), descriptor: Mutex::new(None) }
    }

    /// `/.well-known/aamio-board.json`, read once.
    pub fn descriptor(&self) -> Map<String, Value> {
        let mut cached = self.descriptor.lock().unwrap();
        if cached.is_none() {
            let answer = self.client.call("GET", &format!("{}/.well-known/aamio-board.json", self.host), None, &[]);
            *cached = Some(if answer.status == 200 { answer.body.unwrap_or_default() } else { Map::new() });
        }
        cached.clone().unwrap_or_default()
    }

    /// The work the board advises on a post, capped at what a client does unasked.
    pub fn advised_bits(&self) -> u32 {
        let bits = self.descriptor().get("work").and_then(|w| w.get("advise_bits")).and_then(Value::as_u64).unwrap_or(0) as u32;
        bits.min(ADVISE_MAX_BITS)
    }

    /// Live posts that match; the answer carries posts, next and how_to_answer.
    pub fn find(&self, o: &FindOptions) -> (Answer, Vec<Map<String, Value>>, i64) {
        self.find_with(o, None)
    }

    /// Reads one scope instead of the public board. The key goes in the body
    /// and never in a path. The error says the key was not a key, or that the
    /// answer did not name the scope, in which case it did not read it. A board
    /// older than scopes answers 400, which comes back in the `Answer`.
    pub fn find_in_scope(&self, scope_key: &str, o: &FindOptions) -> Result<(Answer, Vec<Map<String, Value>>, i64), String> {
        let address = scope_address(scope_key)?;
        let (answer, posts, next) = self.find_with(o, Some(scope_key));
        if answer.status == 200 && answer.get("scope").and_then(Value::as_str) != Some(address.as_str()) {
            return Err("the board did not say it read that scope, so its answer is not that scope".to_string());
        }
        Ok((answer, posts, next))
    }

    fn find_with(&self, o: &FindOptions, scope_key: Option<&str>) -> (Answer, Vec<Map<String, Value>>, i64) {
        let mut req = json!({ "after": o.after });
        if let Some(scope_key) = scope_key {
            req["scope_key"] = json!(scope_key);
        }
        if let Some(kind) = &o.kind {
            req["kind"] = json!(kind);
        }
        if !o.tags.is_empty() {
            req["tags"] = json!(o.tags);
        }
        if let Some(lang) = &o.lang {
            req["lang"] = json!(lang);
        }
        if let Some(key) = &o.key {
            req["key"] = json!(key);
        }
        if o.wait > 0 {
            req["wait"] = json!(o.wait.min(25));
        }
        if o.min_work_bits > 0 {
            req["min_work_bits"] = json!(o.min_work_bits);
        }
        let answer = self.client.call("POST", &format!("{}/find", self.host), Some(req.to_string().as_bytes()), &[("Content-Type", "application/json")]);
        let mut posts = Vec::new();
        let mut next = o.after;
        if answer.status == 200 {
            if let Some(n) = answer.get("next").and_then(Value::as_i64) {
                next = n;
            }
            if let Some(list) = answer.get("posts").and_then(Value::as_array) {
                for item in list {
                    if let Value::Object(p) = item {
                        posts.push(p.clone());
                    }
                }
            }
        }
        (answer, posts, next)
    }

    /// One post; 404 once it has expired.
    pub fn get(&self, id: &str) -> Answer {
        self.client.call("GET", &format!("{}/{}", self.host, id), None, &[])
    }

    /// Every tag in use with live counts.
    pub fn tags(&self) -> Answer {
        self.client.call("GET", &format!("{}/tags", self.host), None, &[])
    }

    /// Puts a need or an offer on the board: opens the reply inbox first, any
    /// key but signed only, living longer than the post, signs the post and
    /// does the work the board advises.
    pub fn post(&self, kind: &str, title: &str, text: &str, tags: &[&str], o: &PostOptions) -> Result<Posted, String> {
        let keys = self.client.key_of().ok_or("posting needs keys")?;
        if let Some(scope) = &o.scope {
            if !is_w(scope) {
                return Err("scope is the 20 character address of a scope, from scope_address, and never the key".to_string());
            }
        }
        let ttl = o.ttl.unwrap_or(BOARD_TTL);
        let inbox = self.client.open(ttl + INBOX_MARGIN, Some(&["*"]), None)?;
        if inbox.answer.status != 201 {
            return Ok(Posted { answer: inbox.answer.clone(), inbox });
        }
        let mut post = json!({ "kind": kind, "title": title, "text": text, "tags": tags, "w": inbox.w, "ttl": ttl });
        if let Some(lang) = &o.lang {
            post["lang"] = json!(lang);
        }
        if let Some(deadline) = &o.deadline {
            post["deadline"] = json!(deadline);
        }
        if let Some(scope) = &o.scope {
            // Inside the signed body, so nobody can post the same bytes without it.
            post["scope"] = json!(scope);
        }
        let bytes = post.to_string();
        let sig = keys.sign(&board_signing_input(&keys.public, bytes.as_bytes()));
        let mut headers: Vec<(&str, String)> = vec![("Content-Type", "application/json".into()), ("X-Key", keys.public.clone()), ("X-Sig", sig)];
        let bits = self.advised_bits();
        if bits > 0 {
            headers.push(("X-Work", solve_board(&keys.public, bytes.as_bytes(), bits)?));
        }
        let borrowed: Vec<(&str, &str)> = headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
        let answer = self.client.call("POST", &format!("{}/", self.host), Some(bytes.as_bytes()), &borrowed);
        Ok(Posted { answer, inbox })
    }

    /// An inbox for answers: any key, signed only.
    pub fn reply_inbox(&self, ttl: Option<u32>) -> Result<Thread, String> {
        self.client.open(ttl.unwrap_or(BOARD_TTL + INBOX_MARGIN), Some(&["*"]), None)
    }

    /// Answers a post: a signed write to the post's address, sealed to the
    /// poster's key, carrying the post id and our reply address. `reply_to`
    /// is the `w` of an inbox this client opened and holds the id of.
    pub fn answer(&self, post: &Map<String, Value>, reply_to: &str, text: Option<&str>, data: Option<Value>) -> Result<Sent, String> {
        let keys = self.client.key_of().ok_or("answering needs keys")?;
        let id = post.get("id").and_then(Value::as_str).unwrap_or("");
        let w = post.get("w").and_then(Value::as_str).unwrap_or("");
        let key = post.get("key").and_then(Value::as_str).unwrap_or("");
        if id.is_empty() || !is_w(w) || !is_key(key) {
            return Err("a post has id, w and key".to_string());
        }
        let mut body = json!({ "post": id, "reply_to": reply_to, "from": keys.hash_prefix });
        if let Some(text) = text {
            body["text"] = json!(text);
        }
        if let Some(data) = data {
            body["data"] = data;
        }
        self.client.send(w, body.to_string().as_bytes(), SendOptions { seal_to: Some(key.to_string()), json: true, ..Default::default() })
    }

    /// Answers on an inbox, decoded. Aliases `post_id`, `w`, `reply_address`,
    /// `replyTo`, `reply` and `message` are accepted and named under `renamed`.
    ///
    /// Everything read is returned, answers to other posts included. There is
    /// no post filter here, because a read that filters loses what it
    /// filtered: the cursor returned is the service's, counted over every
    /// message read, so a caller looping on it never sees the dropped ones
    /// again and a library keeps no archive to find them in. Filter the
    /// returned vector on `post`.
    pub fn replies(&self, w: &str, id: &str, after: i64, wait: u32) -> (Answer, Vec<Reply>, i64) {
        let (answer, messages, next) = self.client.read(w, id, after, wait);
        let aliases: [(&str, &[&str]); 3] = [("post", &["post_id"]), ("reply_to", &["w", "reply_address", "replyTo"]), ("text", &["reply", "message"])];
        let mut out = Vec::new();
        for message in messages {
            // An answer in plain text, or an envelope this client cannot open,
            // is still an answer. Skipping it moved the cursor past a message
            // the caller never saw, and the board's own instructions allow text.
            let mut j = message.json.clone().unwrap_or_default();
            let mut renamed = Vec::new();
            for (canonical, names) in aliases.iter() {
                if j.contains_key(*canonical) {
                    continue;
                }
                for alias in names.iter() {
                    if let Some(v) = j.get(*alias).cloned() {
                        j.insert(canonical.to_string(), v);
                        renamed.push((alias.to_string(), canonical.to_string()));
                        break;
                    }
                }
            }
            let post = j.get("post").and_then(Value::as_str).map(str::to_string);
            out.push(Reply {
                post,
                reply_to: j.get("reply_to").and_then(Value::as_str).map(str::to_string),
                text: j.get("text").and_then(Value::as_str).map(str::to_string),
                data: j.get("data").and_then(Value::as_object).cloned(),
                renamed,
                message,
            });
        }
        (answer, out, next)
    }

    /// Takes one of this key's posts off the board.
    pub fn withdraw(&self, id: &str) -> Result<Answer, String> {
        let keys = self.client.key_of().ok_or("withdrawing needs keys")?;
        let body = json!({ "at": now() }).to_string();
        let sig = keys.sign(&board_delete_signing_input(id, body.as_bytes()));
        Ok(self.client.call("DELETE", &format!("{}/{}", self.host, id), Some(body.as_bytes()), &[("Content-Type", "application/json"), ("X-Key", &keys.public), ("X-Sig", &sig)]))
    }
}
