//! A gate kept for an address, and a new inbox at the same address. Found by
//! an outside review on 18 September 2026: the time a kept gate said counted
//! down to nothing and stayed there, and a send to the new inbox was refused
//! on the old one's terms without the service being asked.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use aamio::*;

struct Seen {
    gate_reads: AtomicUsize,
    posts: AtomicUsize,
}

/// Answers the gates in turn, one per read, with the time left beside each,
/// and every post with `post`.
fn serve(gates: Vec<(&'static str, &'static str)>, post: u16) -> (String, Arc<Seen>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Seen { gate_reads: AtomicUsize::new(0), posts: AtomicUsize::new(0) });
    let log = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() || line.is_empty() {
                continue;
            }
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse().unwrap_or(0);
                }
            }
            if length > 0 {
                let mut sink = vec![0u8; length];
                let _ = reader.read_exact(&mut sink);
            }
            let (status, extra, body) = if line.contains("/gate") {
                let i = log.gate_reads.fetch_add(1, Ordering::SeqCst).min(gates.len() - 1);
                (200u16, format!("X-Seconds-Left: {}\r\n", gates[i].1), gates[i].0.to_string())
            } else {
                log.posts.fetch_add(1, Ordering::SeqCst);
                (post, String::new(), r#"{"seq":1,"error":"x","fix":"y"}"#.to_string())
            };
            let answer = format!("HTTP/1.1 {} X\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", status, extra, body.len(), body);
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    (base, seen)
}

const W: &str = "qqqqqqqqqqqqqqqqqqqq";

#[test]
fn a_new_inbox_at_an_old_address_is_asked_about_before_a_no() {
    let (base, seen) = serve(vec![(r#"{"require":{"pow":{"bits":17,"covers":1}}}"#, "0"), ("{}", "600")], 201);
    let client = Client::new(Some(&base), Some(Keys::generate()));
    client.gate(W, false);
    let sent = client.send(W, b"hello", SendOptions::default()).unwrap();
    assert!(!sent.stopped && sent.answer.status == 201, "{}", sent.answer.error());
    assert_eq!(seen.gate_reads.load(Ordering::SeqCst), 2, "one more read of the gate, and only one");
    assert_eq!(seen.posts.load(Ordering::SeqCst), 1);
}

#[test]
fn a_real_no_is_still_a_no_after_one_more_read() {
    let closed = (r#"{"require":{"pow":{"bits":30,"covers":1}}}"#, "0");
    let (base, seen) = serve(vec![closed, closed], 201);
    let client = Client::new(Some(&base), Some(Keys::generate()));
    client.gate(W, false);
    let sent = client.send(W, b"hello", SendOptions::default()).unwrap();
    assert!(sent.stopped);
    assert_eq!(seen.gate_reads.load(Ordering::SeqCst), 2);
    assert_eq!(seen.posts.load(Ordering::SeqCst), 0);
}

#[test]
fn an_inbox_that_answers_410_takes_its_gate_with_it() {
    let (base, _) = serve(vec![("{}", "600")], 410);
    let client = Client::new(Some(&base), Some(Keys::generate()));
    let sent = client.send(W, b"hello", SendOptions::default()).unwrap();
    assert_eq!(sent.answer.status, 410);
    assert!(client.seconds_left(W).is_none(), "the gate and its time went with the inbox");
}
