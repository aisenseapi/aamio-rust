//! A reader checks for itself, and keeps the allowlist it opened a thread with.
//!
//! From a security review on 18 September 2026. `verified` in an answer was the
//! service's word, and `read` took it: the trust model says an operator cannot
//! forge a signature, which is only true for a reader that checks one. And the
//! service holds an allowlist in memory, so a write to an address after its
//! store was emptied opens a thread with no list at all.

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::thread;

use aamio::codec::sha256_hex;
use aamio::*;
use serde_json::{json, Map, Value};

const W: &str = "iiiiiiiiiiiiiiiiiiii";

#[test]
fn normalized_open_and_board_policy_survive_the_server_echo() {
    let alice = keys(1);
    let mut forged = stored(W, 2, "forged", Some(&keys(9)));
    forged["from"] = json!(alice.public);
    let host = reading(vec![stored(W, 1, "unsigned", None), forged]);
    let client = Client::new(Some(&host), Some(keys(1)));
    let combined = format!(" {}, ", alice.public);
    let mut opened = client.open(600, Some(&[&combined, "", &alice.public]), None).unwrap();
    assert_eq!(opened.allow, vec![alice.public.clone()]);
    opened.w = W.to_string();
    let board = Board::new(&client, Some(&host));
    let (_, replies, kept, next) = board.replies_thread(&opened, 0, 0);
    assert!(replies.is_empty());
    assert_eq!(kept.len(), 2);
    assert!(kept[1].unverified_because.as_deref().unwrap().contains("though the service said it did"));
    assert_eq!(next, 2);
    assert_eq!(board.replies(W, &opened.id, 0, 0).1.len(), 2, "compatibility overload remains listless");
    assert_eq!(board.reply_inbox(None).unwrap().allow, vec!["*"]);
    assert_eq!(board.post("need", "local", "only", &[], &PostOptions::default()).unwrap().inbox.allow, vec!["*"]);
    assert!(client.open(600, Some(&[" ", ""]), None).unwrap().allow.is_empty());
    assert_eq!(client.open(600, Some(&["a", " * "]), None).unwrap().allow, vec!["*"]);
}

#[test]
fn legacy_trailing_bits_verify_but_identity_strings_stay_exact() {
    let v: Value = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let a = v["a"]["public"].as_str().unwrap();
    let sig = v["signature"].as_str().unwrap();
    let input = v["signInput"].as_str().unwrap();
    let stray_key = v["strayBits"]["key"].as_str().unwrap();
    assert!(verify(a, v["strayBits"]["signature"].as_str().unwrap(), input));
    assert!(verify(stray_key, sig, input));
    let w = v["w"].as_str().unwrap();
    let mut message = stored(w, 1, v["body"].as_str().unwrap(), None);
    message["from"] = json!(stray_key); message["sig"] = json!(sig);
    let host = reading(vec![message]);
    let client = Client::new(Some(&host), None);
    let held = Thread {id: "key".into(), w: w.into(), allow: vec![a.into()], answer: Answer::default()};
    let (_, got, kept, _) = client.read_thread(&held, 0, 0);
    assert!(got.is_empty()); assert_eq!(kept.len(), 1);
}

#[test]
fn malformed_and_deep_bodies_do_not_end_the_batch() {
    let alice = keys(1);
    let host = reading(vec![stored(W, 1, &"[".repeat(60000), Some(&alice)), Value::Null, json!({"seq":3,"at":3,"body":7,"sha256":[],"verified":true,"from":alice.public}), stored(W, 4, "next", Some(&alice))]);
    let client = Client::new(Some(&host), None);
    let (_, got, next) = client.read(W, "key", 0, 0);
    assert_eq!(got.len(), 4); assert_eq!(next, 4);
    assert!(got[0].json.is_none() && got[3].verified);
    for message in &got[1..3] { assert!(!message.verified && message.from.is_none() && message.opened.is_none() && message.unverified_because.is_some()); }
}

#[test]
fn shortened_receipt_is_not_a_matching_prefix() {
    let v: Value = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let mut receipt: Receipt = serde_json::from_value(v["receipt"].clone()).unwrap();
    receipt.messages.clear();
    assert_eq!(verify_receipt(&receipt, Some(&["seen".into()])).local_hashes_match, Some(false));
}

#[test]
fn shapes_reject_final_newlines() {
    assert!(!is_id(&format!("{}\n", "a".repeat(26))));
    assert!(!is_w(&format!("{}\n", W)));
    assert!(!is_scope_key(&format!("{}\n", "a".repeat(26))));
    assert!(!aamio::codec::is_key(&format!("{}\n", keys(1).public)));
}

fn keys(n: u8) -> Keys {
    Keys::from_seed([n; 32])
}

/// One message as `GET /{w}` returns it, really signed. `None` is an unsigned one.
fn stored(w: &str, seq: i64, body: &str, by: Option<&Keys>) -> Value {
    let mut m = json!({"seq": seq, "at": seq, "type": "text", "body": body, "sha256": sha256_hex(body.as_bytes()), "from": null, "sig": null, "verified": false});
    if let Some(by) = by {
        m["from"] = json!(by.public);
        m["sig"] = json!(by.sign(&thread_signing_input(w, body.as_bytes())));
        m["verified"] = json!(true);
    }
    m
}

fn raw(message: &Value) -> Map<String, Value> {
    message.as_object().unwrap().clone()
}

/// A service that answers every read with these messages; returns its base URL.
fn reading(messages: Vec<Value>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let body = json!({"w": W, "exists": true, "next": messages.len(), "waited": 0, "messages": messages}).to_string();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = match stream {
                Ok(s) => s,
                Err(_) => break,
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).is_err() || header.trim().is_empty() {
                    break;
                }
            }
            let answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
            let _ = stream.write_all(answer.as_bytes());
        }
    });
    base
}

#[test]
fn the_contract_vector_verifies_and_stops_when_anything_moves() {
    let v: Value = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let (w, body, signature, a) = (v["w"].as_str().unwrap(), v["body"].as_str().unwrap(), v["signature"].as_str().unwrap(), v["a"]["public"].as_str().unwrap());
    assert!(verify(a, signature, &thread_signing_input(w, body.as_bytes())), "the contract vector does not verify");
    assert!(!verify(a, signature, &thread_signing_input("aaaaaaaaaaaaaaaaaaaa", body.as_bytes())), "it verified at another address");
    assert!(!verify(a, signature, &thread_signing_input(w, format!("{} ", body).as_bytes())), "it verified over another body");
    assert!(!verify(&keys(1).public, signature, &thread_signing_input(w, body.as_bytes())), "it verified under another key");
}

#[test]
fn what_the_service_calls_verified_has_to_check_out() {
    let alice = keys(1);
    let (verified, why_not, digest) = check_message(W, &raw(&stored(W, 1, "hello", Some(&alice))));
    assert!(verified && why_not.is_none() && digest.map_or(false, |d| d.len() == 64), "a signed message did not verify");
    let (verified, why_not, _) = check_message(W, &raw(&stored(W, 1, "hello", None)));
    assert!(!verified && why_not.is_none(), "an unsigned message is unverified without a complaint");

    let moved = stored("oooooooooooooooooooo", 1, "hello", Some(&alice));
    let mut bare = stored(W, 1, "hello", None);
    bare["verified"] = json!(true);
    let mut wrong_hash = stored(W, 1, "hello", Some(&alice));
    wrong_hash["sha256"] = json!("0".repeat(64));
    let mut no_body = stored(W, 1, "hello", Some(&alice));
    no_body.as_object_mut().unwrap().remove("body");
    for (name, message, want) in [
        ("signed for another address", moved, "though the service said it did"),
        ("verified with nothing to check", bare, "gave no key or signature"),
        ("another hash", wrong_hash, "does not hash"),
        ("no body", no_body, "no body to check"),
    ] {
        let (verified, why_not, _) = check_message(W, &raw(&message));
        assert!(!verified && why_not.as_deref().map_or(false, |why| why.contains(want)), "{}: got {} {:?}", name, verified, why_not);
    }
}

#[test]
fn read_goes_by_its_own_result() {
    let (alice, mallory) = (keys(1), keys(9));
    let mut forged = stored(W, 2, "pay the invoice", Some(&mallory));
    forged["from"] = json!(alice.public);
    let base = reading(vec![stored(W, 1, "hello", Some(&alice)), forged]);
    let (_, messages, _) = Client::new(Some(&base), None).read(W, "read-key", 0, 0);
    assert_eq!(messages.len(), 2);
    assert!(messages[0].verified && messages[0].from.as_deref() == Some(alice.public.as_str()) && messages[0].unverified_because.is_none(), "the signed message: {:?}", messages[0]);
    assert!(
        !messages[1].verified && messages[1].from.is_none() && messages[1].unverified_because.as_deref().map_or(false, |why| why.contains("though the service said it did")),
        "the forged message kept something of its claim: {:?}",
        messages[1]
    );
}

#[test]
fn a_sealed_message_under_a_forged_sender_is_not_opened() {
    let (alice, bob, mallory) = (keys(1), keys(2), keys(9));
    let envelope = mallory.seal(&bob.public, b"for bob").unwrap();
    let mut forged = stored(W, 1, &envelope, Some(&mallory));
    forged["from"] = json!(alice.public);
    forged["sealed"] = json!(true);
    let base = reading(vec![forged]);
    let (_, messages, _) = Client::new(Some(&base), Some(bob)).read(W, "read-key", 0, 0);
    assert!(messages.len() == 1 && messages[0].opened.is_none() && messages[0].format == "sealed-unchecked", "it was opened against the key it claimed: {:?}", messages);
}

#[test]
fn a_sealed_message_that_verifies_still_opens() {
    let (alice, bob) = (keys(1), keys(2));
    let envelope = alice.seal(&bob.public, b"for bob").unwrap();
    let mut sealed = stored(W, 1, &envelope, Some(&alice));
    sealed["sealed"] = json!(true);
    let base = reading(vec![sealed]);
    let (_, messages, _) = Client::new(Some(&base), Some(bob)).read(W, "read-key", 0, 0);
    assert!(messages.len() == 1 && messages[0].opened.as_deref() == Some("for bob") && messages[0].verified, "{:?}", messages);
}

#[test]
fn a_thread_keeps_the_allowlist_it_was_opened_with() {
    let (alice, mallory) = (keys(1), keys(9));
    let mut forged = stored(W, 4, "let me in", Some(&mallory));
    forged["from"] = json!(alice.public);
    let messages = vec![stored(W, 1, "from alice", Some(&alice)), stored(W, 2, "from a stranger", Some(&mallory)), stored(W, 3, "unsigned", None), forged];
    let opened = |allow: Vec<String>| Thread { id: "read-key".to_string(), w: W.to_string(), allow, answer: Answer::default() };

    let client = Client::new(Some(&reading(messages.clone())), None);
    let (_, handed, kept, next) = client.read_thread(&opened(vec![alice.public.clone()]), 0, 0);
    assert!(handed.len() == 1 && handed[0].seq == 1, "named keys handed over {:?}", handed);
    assert!(kept.len() == 3 && kept[0].seq == 2 && kept[0].why.contains("named keys") && next == 4, "named keys kept out {:?}, next {}", kept, next);

    let (_, handed, kept, _) = client.read_thread(&opened(vec!["*".to_string()]), 0, 0);
    assert!(handed.len() == 2 && kept.len() == 2 && kept[0].seq == 3 && kept[0].why.contains("signed messages only"), "any signed key: {:?} {:?}", handed, kept);

    let (_, handed, kept, _) = client.read_thread(&opened(Vec::new()), 0, 0);
    assert!(handed.len() == 4 && kept.is_empty(), "no list: {:?} {:?}", handed, kept);
}
