//! Asking the service for a small answer.
//!
//! The service has taken `X-Limit` and `X-Max-Bytes` since 0.7.2, and no file in
//! this crate sent either. A thread may hold two hundred messages of 65536 bytes,
//! so one read can be about a megabyte. Measured on the live service on 20
//! September 2026: the same thread, 20 529 bytes without the headers and 360 with
//! them.
//!
//! Whole messages only. A signed message cut in half does not verify, so a budget
//! under the first message comes back as `too_large` naming it, never as a piece
//! of it. Nothing here does the cutting: the service does, and this asks and
//! passes on what came back.
//!
//! `read` keeps the signature every caller compiled against and asks for nothing.
//! `read_limited` is the one that asks.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::sync::mpsc::{channel, Receiver};
use std::thread;

use aamio::codec::sha256_hex;
use aamio::*;
use serde_json::{json, Value};

const W: &str = "llllllllllllllllllll";

/// A service that answers one read with `body` and reports the request line and
/// headers it was asked with.
fn watching(body: Value) -> (String, Receiver<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let text = body.to_string();
    let (send, receive) = channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut lines = Vec::new();
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.trim().is_empty() {
                    break;
                }
                lines.push(line.trim().to_string());
            }
            let _ = send.send(lines);
            let answer = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                text.len(),
                text
            );
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    (base, receive)
}

fn keys(n: u8) -> Keys {
    Keys::from_seed([n; 32])
}

/// One message as `GET /{w}` returns it, really signed.
fn stored(w: &str, seq: i64, body: &str, by: &Keys) -> Value {
    json!({"seq": seq, "at": seq, "type": "text", "body": body, "sha256": sha256_hex(body.as_bytes()),
           "from": by.public, "sig": by.sign(&thread_signing_input(w, body.as_bytes())), "verified": true})
}
fn empty() -> Value {
    json!({"w": W, "exists": true, "count": 0, "allow": [], "messages": [], "next": 0, "waited": 0})
}

/// The value of one header in what the service was sent, case-insensitively.
fn header(lines: &[String], name: &str) -> Option<String> {
    lines.iter().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim().eq_ignore_ascii_case(name) {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

#[test]
fn a_read_that_asked_for_nothing_sends_no_limit_header() {
    let (host, seen) = watching(empty());
    let client = Client::new(Some(&host), None);
    client.read(W, "read-key", 0, 0);

    let lines = seen.recv().unwrap();
    assert_eq!(header(&lines, "X-Read").as_deref(), Some("read-key"));
    assert!(header(&lines, "X-Limit").is_none(), "an older service saw a header it never saw before");
    assert!(header(&lines, "X-Max-Bytes").is_none(), "same for the byte budget");
}

#[test]
fn a_count_and_a_budget_reach_the_service() {
    let (host, seen) = watching(empty());
    let client = Client::new(Some(&host), None);
    client.read_limited(W, "read-key", 0, 0, Some(5), Some(4096));

    let lines = seen.recv().unwrap();
    assert_eq!(header(&lines, "X-Limit").as_deref(), Some("5"), "the count did not reach the wire");
    assert_eq!(header(&lines, "X-Max-Bytes").as_deref(), Some("4096"), "the budget did not reach the wire");
}

#[test]
fn each_one_can_be_set_on_its_own() {
    let (host, seen) = watching(empty());
    let client = Client::new(Some(&host), None);
    client.read_limited(W, "read-key", 0, 0, Some(3), None);
    let lines = seen.recv().unwrap();
    assert_eq!(header(&lines, "X-Limit").as_deref(), Some("3"));
    assert!(header(&lines, "X-Max-Bytes").is_none());

    let (host, seen) = watching(empty());
    let client = Client::new(Some(&host), None);
    client.read_limited(W, "read-key", 0, 0, None, Some(2048));
    let lines = seen.recv().unwrap();
    assert!(header(&lines, "X-Limit").is_none());
    assert_eq!(header(&lines, "X-Max-Bytes").as_deref(), Some("2048"));
}

#[test]
fn what_was_left_behind_comes_back() {
    let mut body = empty();
    body["more"] = json!(true);
    body["next"] = json!(12);
    let (host, _seen) = watching(body);
    let client = Client::new(Some(&host), None);
    let (answer, _, next) = client.read_limited(W, "read-key", 0, 0, Some(2), None);

    assert_eq!(answer.get("more").and_then(Value::as_bool), Some(true), "more was dropped, so a short answer reads like an empty thread");
    assert_eq!(next, 12, "next must be the last message handed over, or the next read steps over one");
}

#[test]
fn a_message_too_large_for_the_budget_is_named_not_cut() {
    let mut body = empty();
    body["too_large"] = json!({"seq": 7, "bytes": 70000, "fix": "Raise X-Max-Bytes above 70000 or read this one on its own."});
    let (host, _seen) = watching(body);
    let client = Client::new(Some(&host), None);
    let (answer, _, _) = client.read_limited(W, "read-key", 0, 0, None, Some(1024));

    let named = answer.get("too_large").expect("a budget too small for the first message came back with nothing to act on");
    assert!(named.get("fix").is_some(), "too_large without a fix leaves the caller to guess at a number");
}

#[test]
fn the_limits_ride_along_with_wait_and_a_cursor() {
    let (host, seen) = watching(empty());
    let client = Client::new(Some(&host), None);
    client.read_limited(W, "read-key", 9, 3, Some(4), None);

    let lines = seen.recv().unwrap();
    assert!(lines[0].contains(&format!("/{}/after/9/wait/3", W)), "the path lost the cursor or the wait: {}", lines[0]);
    assert_eq!(header(&lines, "X-Limit").as_deref(), Some("4"));
}

#[test]
fn read_thread_limited_still_keeps_the_allowlist() {
    let alice = keys(1);
    let stranger = keys(9);
    let mut body = empty();
    body["messages"] = json!([stored(W, 1, "from a partner", &alice), stored(W, 2, "from a stranger", &stranger)]);
    body["next"] = json!(2);

    let (host, seen) = watching(body);
    let client = Client::new(Some(&host), None);
    let thread = Thread { w: W.to_string(), id: "read-key".to_string(), allow: vec![alice.public.clone()], answer: Answer::default() };
    let (_, handed, kept, _) = client.read_thread_limited(&thread, 0, 0, Some(2), Some(4096));

    let lines = seen.recv().unwrap();
    assert_eq!(header(&lines, "X-Limit").as_deref(), Some("2"), "the limits did not reach the wire through read_thread");
    assert_eq!(header(&lines, "X-Max-Bytes").as_deref(), Some("4096"));
    assert_eq!(handed.len(), 1, "a smaller answer must not become a looser one");
    assert_eq!(handed[0].seq, 1);
    assert_eq!(kept.len(), 1, "what the list kept out is still said out loud");
}
