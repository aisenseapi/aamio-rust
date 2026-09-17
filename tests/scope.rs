//! Scopes on the board against a board on localhost that answers as told and
//! records what it was sent: a post carries the address inside what is signed,
//! and a find sends the key in the body and believes only an answer that names
//! the scope.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;

use aamio::*;
use serde_json::Value;

const KEY: &str = "aamioscopevector0000000000";
const ADDRESS: &str = "2o3wek6doqhqatib63vj";

#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

type Answers = Arc<Mutex<Vec<(u16, String)>>>;

/// A board that answers each request with the next answer given, and keeps what it saw.
fn serve(answers: Answers) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
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
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let mut headers = Vec::new();
            let mut length = 0usize;
            loop {
                let mut header = String::new();
                reader.read_line(&mut header).unwrap();
                let header = header.trim_end().to_string();
                if header.is_empty() {
                    break;
                }
                if let Some((name, value)) = header.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                    headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
                }
            }
            let mut body = vec![0u8; length];
            reader.read_exact(&mut body).unwrap();
            log.lock().unwrap().push(Seen { method, path, headers, body: String::from_utf8(body).unwrap() });
            let (status, text) = {
                let mut queue = answers.lock().unwrap();
                if queue.is_empty() { (404, "{\"error\":\"nothing left in the fake\",\"fix\":\"none\"}".to_string()) } else { queue.remove(0) }
            };
            let response = format!("HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", status, text.len(), text);
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (base, seen)
}

#[test]
fn a_post_in_a_scope_carries_the_address_inside_what_is_signed() {
    let answers: Answers = Arc::new(Mutex::new(vec![
        (201, "{\"w\":\"x\",\"expire_at\":4102444800,\"allow\":[\"*\"]}".to_string()),
        (200, "{\"work\":{\"advise_bits\":0}}".to_string()),
        (201, "{\"id\":\"pppppppppppppppppppp\"}".to_string()),
    ]));
    let (base, seen) = serve(answers);
    let client = Client::new(Some(&base), Some(Keys::generate()));
    let board = Board::new(&client, Some(&base));

    let posted = board.post("need", "Chapter 3 draft ready", "At commit 4f2a9c1.", &["chapter-03"], &PostOptions { ttl: Some(900), scope: Some(ADDRESS.to_string()), ..Default::default() }).unwrap();
    assert_eq!(posted.answer.status, 201);

    let sent = seen.lock().unwrap().last().cloned().unwrap();
    let fields: Value = serde_json::from_str(&sent.body).unwrap();
    assert_eq!(sent.method, "POST");
    assert_eq!(fields["scope"], ADDRESS);
    assert!(!sent.body.contains(KEY), "never the key");
    let keys = client.keys.as_ref().unwrap();
    let sig = sent.headers.iter().find(|(n, _)| n == "x-sig").map(|(_, v)| v.clone()).unwrap();
    assert!(verify(&keys.public, &sig, &board_signing_input(&keys.public, sent.body.as_bytes())), "inside what is signed");

    assert!(board.post("need", "t", "x", &[], &PostOptions { scope: Some(KEY.to_string()), ..Default::default() }).is_err(), "a key where the address goes is refused");
}

#[test]
fn a_find_in_a_scope_believes_only_an_answer_that_names_it() {
    let answers: Answers = Arc::new(Mutex::new(vec![
        (200, format!("{{\"count\":1,\"live\":1,\"next\":3,\"posts\":[{{\"id\":\"pppppppppppppppppppp\"}}],\"scope\":\"{}\"}}", ADDRESS)),
        (200, "{\"count\":0,\"live\":0,\"next\":0,\"posts\":[]}".to_string()),
        (400, "{\"error\":\"Unknown field scope_key\",\"fix\":\"Drop that field\"}".to_string()),
        (200, "{\"count\":0,\"live\":0,\"next\":0,\"posts\":[]}".to_string()),
    ]));
    let (base, seen) = serve(answers);
    let client = Client::new(Some(&base), None);
    let board = Board::new(&client, Some(&base));

    let (answer, posts, next) = board.find_in_scope(KEY, &FindOptions { tags: vec!["chapter-03".into()], ..Default::default() }).unwrap();
    assert!(answer.status == 200 && posts.len() == 1 && next == 3);
    let first = seen.lock().unwrap()[0].clone();
    let sent: Value = serde_json::from_str(&first.body).unwrap();
    assert_eq!(sent["scope_key"], KEY);
    assert!(!first.path.contains(KEY), "the key goes in the body and never in the path");

    let refused = board.find_in_scope(KEY, &FindOptions::default()).unwrap_err();
    assert!(refused.contains("did not say it read that scope"));

    let (old, _, _) = board.find_in_scope(KEY, &FindOptions::default()).unwrap();
    assert_eq!(old.status, 400, "a board older than scopes refuses, and the refusal comes back");

    assert!(board.find_in_scope(ADDRESS, &FindOptions::default()).is_err(), "the address is refused where the key goes");

    board.find(&FindOptions::default());
    let public: Value = serde_json::from_str(&seen.lock().unwrap().last().unwrap().body).unwrap();
    assert!(public.get("scope_key").is_none(), "find reads the public board");
}
