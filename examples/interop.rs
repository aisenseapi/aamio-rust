//! The Rust side of tests/interop.py: reads one JSON object on stdin, opens
//! what Python sealed, verifies what Python signed, seals and signs for
//! Python, and prints one JSON object. Nothing touches the network.
//!
//!     cargo run --example interop < request.json

use std::io::Read;

use aamio::{verify, Keys};
use serde_json::{json, Value};

fn main() {
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).expect("stdin");
    let req: Value = serde_json::from_str(&input).expect("json in");
    let keys = Keys::from_seed_hex(req["rust_seed"].as_str().unwrap()).expect("seed");
    let py_public = req["py_public"].as_str().unwrap();
    let signing_input = req["signing_input"].as_str().unwrap();
    let opened = keys.open(py_public, req["envelope_from_py"].as_str().unwrap()).expect("open");
    let sealed = keys.seal(py_public, req["plaintext_for_py"].as_str().unwrap().as_bytes()).expect("seal");
    let out = json!({
        "rust_public": keys.public,
        "opened": String::from_utf8(opened).unwrap(),
        "py_signature_verifies": verify(py_public, req["py_signature"].as_str().unwrap(), signing_input),
        "envelope_from_rust": sealed,
        "rust_signature": keys.sign(signing_input),
    });
    println!("{}", out);
}
