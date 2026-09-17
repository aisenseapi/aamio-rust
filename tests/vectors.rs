//! The vectors every client shares, reproduced here with nothing in between.
//! `testdata/vectors.json` is the file aamio-js keeps; the gate vectors are
//! the ones the service, aamio-python, aamio-php and aamio-go check.

use aamio::codec::{b64url, base32, is_key, sha256_hex, unb64url};
use aamio::*;
use serde_json::{json, Value};

fn vectors() -> Value {
    serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap()
}

fn s<'a>(v: &'a Value, path: &[&str]) -> &'a str {
    let mut cur = v;
    for p in path {
        cur = &cur[*p];
    }
    cur.as_str().unwrap()
}

#[test]
fn encodings() {
    let v = vectors();
    assert_eq!(sha256_hex(b"abc"), s(&v, &["sha256_abc"]));
    assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
    assert_eq!(unb64url("+/8=").unwrap(), vec![0xfb, 0xff], "standard base64 with padding is accepted too");
    assert_eq!(base32(b""), "");
    assert!(is_key(s(&v, &["a", "public"])) && !is_key("short"));
}

#[test]
fn addresses() {
    let v = vectors();
    assert_eq!(w(s(&v, &["id"])).unwrap(), s(&v, &["w"]));
    assert_eq!(w("aamio0000000000000000000ok").unwrap(), "5d6gubrpdewztqru2nmi");
    let id = new_id();
    assert!(id.len() == 26 && is_id(&id) && is_w(&w(&id).unwrap()));
    assert!(w("short").is_err(), "a short id is refused before it is hashed");
}

#[test]
fn scopes() {
    let v = vectors();
    let key = s(&v, &["scope", "key"]);
    assert_eq!(scope_address(key).unwrap(), s(&v, &["scope", "address"]));
    assert_eq!(w(key).unwrap(), s(&v, &["scope", "thread_w_of_the_same_string"]), "the thread address of the same string is another");
    let fresh = new_scope_key();
    assert!(fresh.len() == 26 && is_scope_key(&fresh));
    let address = scope_address(&fresh).unwrap();
    assert!(is_w(&address) && !is_scope_key(&address), "an address is never a key");
    assert!(scope_address(s(&v, &["scope", "address"])).is_err(), "an address is refused where the key goes");
}

#[test]
fn keys() {
    let v = vectors();
    let a = Keys::from_seed_hex(s(&v, &["a", "seed"])).unwrap();
    let b = Keys::from_seed_hex(s(&v, &["b", "seed"])).unwrap();
    assert_eq!(a.public, s(&v, &["a", "public"]));
    assert_eq!(b.public, s(&v, &["b", "public"]));
    assert_eq!(a.hash, s(&v, &["a", "hash"]));
    assert_eq!(a.hash_prefix, &s(&v, &["a", "hash"])[..8]);
    assert_eq!(hex::encode(curve_public(&a.public).unwrap()), s(&v, &["a", "curvePublic"]), "X25519 public of A");
    assert_eq!(hex::encode(curve_public(&b.public).unwrap()), s(&v, &["b", "curvePublic"]), "X25519 public of B");
    let input = thread_signing_input(s(&v, &["w"]), s(&v, &["body"]).as_bytes());
    assert_eq!(input, s(&v, &["signInput"]));
    assert_eq!(a.sign(&input), s(&v, &["signature"]), "the signature of A, byte for byte");
    assert!(verify(&a.public, s(&v, &["signature"]), &input));
    assert!(!verify(&b.public, s(&v, &["signature"]), &input));
    assert!(!verify(&a.public, s(&v, &["signature"]), &format!("{}x", input)));
    assert_eq!(Keys::from_seed(a.seed()).public, a.public, "a key rebuilt from its seed is the same key");
    assert_ne!(Keys::generate().public, Keys::generate().public);
}

#[test]
fn sealing() {
    let v = vectors();
    let a = Keys::from_seed_hex(s(&v, &["a", "seed"])).unwrap();
    let b = Keys::from_seed_hex(s(&v, &["b", "seed"])).unwrap();
    let opened = b.open(&a.public, s(&v, &["envelopeFromAToB"])).unwrap();
    assert_eq!(String::from_utf8(opened).unwrap(), s(&v, &["plaintext"]), "B opens the envelope A sealed, made by PyNaCl");
    let envelope = a.seal(&b.public, "fra rust til hvem som helst".as_bytes()).unwrap();
    assert!(envelope.starts_with(&format!("{{\"e2ee\":\"nacl.box.v1\",\"to\":\"{}\",\"nonce\":\"", b.hash_prefix)));
    assert!(is_envelope(&envelope) && !is_envelope("{\"hello\":\"plain\"}"));
    assert_eq!(b.open(&a.public, &envelope).unwrap(), "fra rust til hvem som helst".as_bytes());
    assert!(a.open(&b.public, &envelope).unwrap_err().contains("sealed to"), "A is told whom it was sealed to");
    assert!(b.open(&Keys::generate().public, &envelope).is_err(), "does not open with the wrong sender key");
    assert_ne!(a.seal(&b.public, b"x").unwrap(), a.seal(&b.public, b"x").unwrap(), "a fresh nonce every time");
}

#[test]
fn receipt_root() {
    let v = vectors();
    let receipt: Receipt = serde_json::from_value(v["receipt"].clone()).unwrap();
    assert_eq!(root(&receipt.messages), receipt.root, "the root recomputed from the lines is the published root");
    let check = verify_receipt(&receipt, None);
    assert!(check.root_adds_up && check.commitment_matches && check.local_root_matches.is_none());
    let mut reversed = receipt.messages.clone();
    reversed.reverse();
    assert_eq!(root(&reversed), receipt.root, "the order the lines arrive in does not matter, seq does");
    let mut broken = receipt.clone();
    broken.messages[0].sha256 = "0".repeat(64);
    assert!(!verify_receipt(&broken, None).root_adds_up, "one changed hash breaks the root");
    let hashes: Vec<String> = receipt.messages.iter().map(|m| m.sha256.clone()).collect();
    assert_eq!(verify_receipt(&receipt, Some(&hashes)).local_root_matches, Some(true));
    assert_eq!(verify_receipt(&receipt, Some(&hashes[..1])).local_root_matches, None, "fewer local hashes is not a failure");
}

const GATE_W: &str = "b4netymg7r5nnt2yiscp";
const GATE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const GATE_BODY: &str = "{\"post\":\"abc\",\"reply_to\":\"xyz\",\"text\":\"hei\"}";
const GATE_SHA: &str = "36751f20147f74e3dfbaf829fb8f04ea9ed596268bd685a69fdfa5992fddd6b8";

#[test]
fn gate_vectors() {
    assert_eq!(sha256_hex(GATE_BODY.as_bytes()), GATE_SHA);
    let signed = pow_digest(GATE_W, GATE_KEY, GATE_SHA, "7036");
    assert_eq!(hex::encode(signed), "00003a2ac769f2265d621969d9ff1feaaa2b9dcc6f006b6adae1d22c2db8a842");
    assert_eq!(zero_bits(&signed), 18);
    let unsigned = pow_digest(GATE_W, "", GATE_SHA, "91617");
    assert_eq!(hex::encode(unsigned), "000018b5cc286cf27d2c97296aff9e2e60db0c165e7cf3af7a44857423c08612");
    assert_eq!(zero_bits(&unsigned), 19);
    assert!(pow_input(GATE_W, "", GATE_SHA, "1").contains("\n\n"), "an unsigned message puts an empty key in the input");
    for digest in [
        pow_digest(GATE_W, &"B".repeat(43), GATE_SHA, "7036"),
        pow_digest(GATE_W, "", GATE_SHA, "7036"),
        pow_digest("aaaaaaaaaaaaaaaaaaaa", GATE_KEY, GATE_SHA, "7036"),
        pow_digest(GATE_W, GATE_KEY, &"0".repeat(64), "7036"),
    ] {
        assert!(zero_bits(&digest) < 16, "work is bound to what it was done for");
    }
    assert_eq!(zero_bits(&[0u8; 32]), 256);
    assert_eq!(zero_bits(&[0x00, 0x0f, 0xff]), 12);
    assert_eq!(zero_bits(&[0x80]), 0);
    assert_eq!(zero_bits(&[0x01]), 7);
    let nonce = solve(GATE_W, GATE_KEY, GATE_BODY.as_bytes(), 8).unwrap();
    assert!(is_nonce(&nonce) && zero_bits(&pow_digest(GATE_W, GATE_KEY, GATE_SHA, &nonce)) >= 8);
    let board_nonce = solve_board(GATE_KEY, GATE_BODY.as_bytes(), 6).unwrap();
    assert!(zero_bits(&board_pow_digest(GATE_KEY, GATE_SHA, &board_nonce)) >= 6);
    assert!(board_pow_input(GATE_KEY, GATE_SHA, "1").starts_with("aamio-board-pow-v1\n"));
}

#[test]
fn canonical_form() {
    let g = json!({"advise":{"pow":{"covers":1,"bits":16}},"require":{}});
    assert_eq!(canonical(&g), "{\"advise\":{\"pow\":{\"bits\":16,\"covers\":1}}}", "keys sorted, empty bucket removed");
    assert_eq!(gate_hash(&g), "de2a8fd4c8d7cbf9f6839c810632caf2c4b40fd8ba99ad19678f6c5b063d4d64");
    let e = json!({"require":{},"advise":{}});
    assert_eq!(canonical(&e), "{}");
    assert_eq!(gate_hash(&e), "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a");
    let points = [0x61u32, 0x22, 0x62, 0x5C, 0x63, 0x2F, 0x64, 0x01, 0x65, 0x1F, 0x66, 0x0A, 0x67, 0xE6, 0x68, 0x2028, 0x69, 0x1F600, 0x6A, 0x7F];
    let string: String = points.iter().map(|p| char::from_u32(*p).unwrap()).collect();
    let text = canonical(&json!({ "s": string }));
    assert_eq!(hex::encode(text.as_bytes()), "7b2273223a22615c22625c5c632f645c7530303031655c7530303166665c6e67c3a668e280a869f09f98806a7f227d", "a string escapes only where JSON requires it");
    assert_eq!(sha256_hex(text.as_bytes()), "b089754be373b84fb2b5fd2d6db856363986712915c98a5f7a412ff38b313b63");
}

#[test]
fn the_plan() {
    assert_eq!(plan(None), Plan::default(), "no gate: nothing to do");
    assert_eq!(plan(Some(&json!({}))), Plan::default());
    let p = plan(Some(&json!({"advise":{"pow":{"bits":16,"covers":1}}})));
    assert_eq!(p.bits, Some(16));
    assert!(p.stop.is_none());
    let p = plan(Some(&json!({"advise":{"pow":{"bits":19}}})));
    assert!(p.bits.is_none() && p.notes.len() == 1, "advised 19 bits are passed over with a note");
    let p = plan(Some(&json!({"require":{"pow":{"bits":20,"covers":1},"per_key":3,"write_until":1800000000}})));
    assert!(p.bits == Some(20) && p.stop.is_none(), "required 20 bits are done; per_key and write_until are known");
    let p = plan(Some(&json!({"require":{"pow":{"bits":21}}})));
    assert!(p.stop.unwrap().contains("21"));
    let p = plan(Some(&json!({"require":{"captcha":true}})));
    assert!(p.stop.unwrap().contains("captcha"));
    let p = plan(Some(&json!({"advise":{"captcha":true,"pow":{"bits":8}}})));
    assert!(p.stop.is_none() && p.bits == Some(8) && p.notes.len() == 1);
    assert_eq!((REQUIRE_MAX_BITS, ADVISE_MAX_BITS), (20, 18));
}

#[test]
fn sealing_with_a_given_nonce_reproduces_the_vector() {
    let v = vectors();
    let a = Keys::from_seed_hex(s(&v, &["a", "seed"])).unwrap();
    let envelope: Value = serde_json::from_str(s(&v, &["envelopeFromAToB"])).unwrap();
    let nonce: [u8; 24] = unb64url(envelope["nonce"].as_str().unwrap()).unwrap().try_into().unwrap();
    let sealed = a.seal_with_nonce(s(&v, &["b", "public"]), s(&v, &["plaintext"]).as_bytes(), nonce).unwrap();
    assert_eq!(sealed, s(&v, &["envelopeFromAToB"]), "the same keys, plaintext and nonce give PyNaCl's envelope byte for byte");
}

#[test]
fn the_solver_finds_the_nonce_the_slow_way_finds() {
    let w = "b4netymg7r5nnt2yiscp";
    let body: &[u8] = br#"{"post":"abc","reply_to":"xyz","text":"hei"}"#;
    let key = "A".repeat(43);
    let sha = sha256_hex(body);
    for bits in [0u32, 1, 8, 12] {
        let slow = (0u64..).find(|n| zero_bits(&pow_digest(w, &key, &sha, &n.to_string())) >= bits).unwrap().to_string();
        assert_eq!(solve(w, &key, body, bits).unwrap(), slow);
        assert_eq!(solve_hashed(w, &key, &sha, bits).unwrap(), slow);
        let slow_board = (0u64..).find(|n| zero_bits(&board_pow_digest(&key, &sha, &n.to_string())) >= bits).unwrap().to_string();
        assert_eq!(solve_board(&key, body, bits).unwrap(), slow_board);
        assert_eq!(solve_board_hashed(&key, &sha, bits).unwrap(), slow_board);
    }
    assert!(solve_hashed(w, &key, &sha, 21).is_err(), "above the ceiling is refused, not attempted");
}
