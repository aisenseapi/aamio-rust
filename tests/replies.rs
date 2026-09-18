//! `replies` used to take a post id and drop everything that did not match.
//! The cursor it hands back is the service's, counted over every message read,
//! so a caller looping on it never saw the dropped ones again, and a library
//! keeps no archive to find them in. The filter is gone. Everything read comes
//! back, and the caller filters the vector it holds.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::thread;

use aamio::*;

/// A service that answers one read and then closes.
fn serve(body: &'static str) -> String {
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
            let answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    base
}

#[test]
fn replies_hands_over_every_message_it_read() {
    let base = serve(
        r#"{"next":7,"messages":[
            {"seq":5,"at":1,"verified":true,"from":"k","sha256":"a","body":"{\"post\":\"p1\",\"text\":\"for p1\"}"},
            {"seq":6,"at":2,"verified":true,"from":"k","sha256":"b","body":"{\"post\":\"p2\",\"text\":\"for another post\"}"},
            {"seq":7,"at":3,"verified":true,"from":"k","sha256":"c","body":"a stranger answering in words"}
        ]}"#,
    );
    let client = Client::new(Some(&base), Some(Keys::generate()));
    let board = Board::new(&client, Some(&base));

    let (answer, replies, next) = board.replies("wwwwwwwwwwwwwwwwwwww", "read-key", 0, 0);

    assert_eq!(answer.status, 200);
    assert_eq!(replies.len(), 3, "every message read is one the caller gets to see");
    assert_eq!(replies[0].post.as_deref(), Some("p1"));
    assert_eq!(replies[1].post.as_deref(), Some("p2"), "an answer to another post is still handed over");
    assert_eq!(replies[2].post, None, "a plain text answer names no post and is kept all the same");
    // The cursor covers exactly what came back, so a caller that walks it
    // loses nothing on the way.
    assert_eq!(next, 7);
    assert_eq!(replies[2].message.seq, 7);
}
