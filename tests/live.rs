//! One thread end to end against a running aamio, then a gate with work,
//! presence, and the board's read side. Nothing secret is left behind: every
//! thread is closed and would expire in two minutes anyway. The board is only
//! read. Ignored by default; run with:
//!
//!     cargo test --test live -- --ignored --nocapture
//!
//! AAMIO_HOST overrides https://aamio.at.

use aamio::*;
use serde_json::{json, Value};
use std::time::Instant;

#[test]
#[ignore]
fn live() {
    let host = std::env::var("AAMIO_HOST").ok();
    let me = Keys::generate();
    let partner = Keys::generate();
    let client = Client::new(host.as_deref(), Some(me.clone()));
    let other = Client::new(host.as_deref(), Some(partner.clone()));

    let thread = client.open(120, Some(&[me.public.as_str(), partner.public.as_str()]), None).unwrap();
    assert_eq!(thread.answer.status, 201, "open: {}", thread.answer.error());

    let sent = client.send(&thread.w, b"hello from rust", SendOptions::default()).unwrap();
    assert_eq!(sent.answer.status, 201, "signed text write: {}", sent.answer.error());
    assert_eq!(sent.answer.get("verified"), Some(&Value::Bool(true)));
    let sealed = other.send(&thread.w, br#"{"tender":"ARC-4471"}"#, SendOptions { seal_to: Some(me.public.clone()), json: true, ..Default::default() }).unwrap();
    assert_eq!(sealed.answer.status, 201, "sealed write: {}", sealed.answer.error());
    assert_eq!(sealed.answer.get("sealed"), Some(&Value::Bool(true)));
    let stranger = Client::new(host.as_deref(), Some(Keys::generate()));
    let refused = stranger.send(&thread.w, b"x", SendOptions::default()).unwrap();
    assert_eq!(refused.answer.status, 403);
    assert!(refused.answer.get("fix").is_some(), "a refusal carries a fix");

    let (answer, messages, next) = client.read(&thread.w, &thread.id, 0, 0);
    assert_eq!(answer.status, 200);
    assert_eq!(messages.len(), 2);
    assert_eq!(next, 2);
    assert!(messages[0].format == "text" && messages[0].body == "hello from rust" && messages[0].verified);
    assert!(messages[1].format == "sealed" && messages[1].from.as_deref() == Some(partner.public.as_str()));
    assert_eq!(messages[1].json.as_ref().unwrap()["tender"], "ARC-4471");
    let started = Instant::now();
    let (answer, waited, _) = client.read(&thread.w, &thread.id, 2, 3);
    assert!(answer.status == 200 && waited.is_empty() && started.elapsed().as_millis() >= 2500, "a long poll on nothing waits");

    let (answer, receipt, check) = client.receipt(&thread.w, &thread.id);
    assert_eq!(answer.status, 200);
    let check = check.unwrap();
    assert!(check.root_adds_up && check.commitment_matches);
    assert_eq!(receipt.unwrap().count, 2);
    assert_eq!(client.close(&thread.w, &thread.id).status, 200);

    // gate
    let gated = client.open(120, Some(&["*"]), Some(&json!({"advise":{"pow":{"bits":8}}}))).unwrap();
    assert_eq!(gated.answer.status, 201);
    let gate = client.gate(&gated.w, true).unwrap();
    assert_eq!(gate_hash(&gate), gate_hash(&json!({"advise":{"pow":{"bits":8,"covers":1}}})), "gate read back, canonical");
    let worked = client.send(&gated.w, b"with work", SendOptions::default()).unwrap();
    assert_eq!(worked.answer.status, 201, "{}", worked.answer.error());
    assert!(worked.work.is_some());
    assert_eq!(worked.answer.get("met").and_then(|m| m.get("pow")).and_then(Value::as_u64), Some(8));
    let required = client.open(120, Some(&["*"]), Some(&json!({"require":{"pow":{"bits":10}}}))).unwrap();
    let first = client.send(&required.w, b"required", SendOptions::default()).unwrap();
    assert_eq!(first.answer.status, 201, "required work is done before the first attempt");
    client.close(&gated.w, &gated.id);
    client.close(&required.w, &required.id);

    // presence
    let inbox = client.open(120, None, None).unwrap();
    assert_eq!(client.presence_publish(&inbox.w, &["rust.test"], 30).unwrap().status, 200);
    assert_eq!(client.presence_get(&me.public).status, 200);
    let found = client.presence_lookup(&[me.hash_prefix.as_str()], 0);
    assert_eq!(found.get("count").and_then(Value::as_u64), Some(1));
    assert_eq!(client.presence_delete().unwrap().status, 200);
    assert_eq!(client.presence_get(&me.public).status, 404);
    client.close(&inbox.w, &inbox.id);

    // board, read side
    let board = Board::new(&client, None);
    assert!(board.advised_bits() > 0, "the board descriptor says what work it advises");
    let (answer, _posts, _) = board.find(&FindOptions::default());
    assert_eq!(answer.status, 200);
    assert_eq!(board.tags().status, 200);
    let reply = board.reply_inbox(Some(120)).unwrap();
    assert_eq!(reply.answer.status, 201);
    assert_eq!(reply.answer.get("allow"), Some(&json!(["*"])));
    client.close(&reply.w, &reply.id);
}
