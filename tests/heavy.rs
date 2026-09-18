//! Work up to 32 bits, for an inbox that means to meet only writers with
//! compute. 32 bits can take hours and an inbox lives an hour at most, so the
//! time left is read from X-Seconds-Left on the gate, work that would not be
//! done by then is not started, and work that runs over is stopped.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use aamio::*;
use serde_json::json;

#[test]
fn work_that_cannot_fit_is_not_started_and_work_that_fits_goes_ahead() {
    // A minute: no loop like this one does 32 bits in that, on any machine.
    let p = plan_within(Some(&json!({"require":{"pow":{"bits":32,"covers":1}}})), Some(60.0));
    let stop = p.stop.expect("32 bits with a minute left is not started");
    assert!(stop.contains("not started") && stop.contains("nothing was sent"), "{}", stop);

    let p = plan_within(Some(&json!({"require":{"pow":{"bits":20,"covers":1}}})), Some(3600.0));
    assert!(p.stop.is_none() && p.bits == Some(20) && p.expected_seconds > 0.0);
    assert!(plan(Some(&json!({"require":{"pow":{"bits":32}}}))).stop.is_none(), "without a time left the plan is what it was");
}

#[test]
fn work_past_its_deadline_is_stopped() {
    let start = Instant::now();
    let found = solve_until("wwwwwwwwwwwwwwwwwwww", &"k".repeat(43), b"body", 32, Some(Instant::now() + Duration::from_millis(300))).unwrap();
    assert!(found.is_none() && start.elapsed() < Duration::from_secs(5));
    let (e21, e20) = (expected_seconds(21), expected_seconds(20));
    assert!((e21 - 2.0 * e20).abs() < 1e-9 * e21.max(1.0), "the estimate doubles with each bit");
    assert_eq!(describe_seconds(600.0), "10 minutes");
    assert!(hash_rate() > 0.0);
}

/// A service whose gate asks for 26 bits and says five seconds are left, and
/// that counts the posts it is sent.
fn serve(posts: Arc<AtomicUsize>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
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
            let (extra, body) = if line.contains("/gate") {
                ("X-Seconds-Left: 5\r\n", r#"{"require":{"pow":{"bits":26,"covers":1}}}"#)
            } else {
                posts.fetch_add(1, Ordering::SeqCst);
                ("", r#"{"seq":1}"#)
            };
            let answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{}Content-Length: {}\r\nConnection: close\r\n\r\n{}", extra, body.len(), body);
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    base
}

#[test]
fn the_seconds_left_come_from_the_gate_and_a_send_that_cannot_fit_sends_nothing() {
    let posts = Arc::new(AtomicUsize::new(0));
    let base = serve(posts.clone());
    let client = Client::new(Some(&base), Some(Keys::generate()));
    let w = "qqqqqqqqqqqqqqqqqqqq";

    let sent = client.send(w, b"hello", SendOptions::default()).unwrap();

    assert!(sent.stopped && sent.answer.error().contains("not started"), "{}", sent.answer.error());
    assert_eq!(posts.load(Ordering::SeqCst), 0, "nothing left the machine");
    let left = client.seconds_left(w).expect("the gate said how long");
    assert!(left <= 5.0 && left > 4.0);
}
