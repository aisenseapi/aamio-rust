//! The aamio protocol core for JavaScript hosts, compiled to WebAssembly.
//!
//! No transport: fetch, headers, retries and everything else about HTTP stay
//! in the host, which is where they already are in `aamio-js`. What is here is
//! what is worth sharing with the Rust client bit for bit: proof of work, the
//! canonical gate, and keys, signing and sealing.
//!
//! The proof of work is one call that runs the whole search, because a host
//! that crossed into WebAssembly once per hash would spend its time crossing.
//!
//! Keys are passed as their 32 seed bytes on every call and nothing is kept
//! between calls, so there is no object to free and no state to leak.

use aamio::Keys;
use wasm_bindgen::prelude::*;

fn keys(seed: &[u8]) -> Result<Keys, JsError> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| JsError::new("a seed is 32 bytes"))?;
    Ok(Keys::from_seed(seed))
}

fn refused(reason: String) -> JsError {
    JsError::new(&reason)
}

fn gate(gate_json: &str) -> Result<serde_json::Value, JsError> {
    let value: serde_json::Value = serde_json::from_str(gate_json).map_err(|e| JsError::new(&format!("a gate is a JSON object: {}", e)))?;
    if !value.is_object() {
        return Err(JsError::new("a gate is a JSON object"));
    }
    Ok(value)
}

/// The version of the core this module was built from.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------------------------------------------------------------------- work --

/// The first nonce, counting from 0, whose thread digest reaches `bits`: the
/// X-Work value. `key` is the X-Key exactly as sent, or "" for an unsigned
/// message. `bodySha256` is lowercase hex over the exact bytes sent. At most 20
/// bits, the most an inbox may require.
#[wasm_bindgen(js_name = solvePow)]
pub fn solve_pow(w: &str, key: &str, body_sha256: &str, bits: u32) -> Result<String, JsError> {
    aamio::solve_hashed(w, key, body_sha256, bits).map_err(refused)
}

/// The same for a board post: no address, a post is not to a thread.
#[wasm_bindgen(js_name = solveBoardPow)]
pub fn solve_board_pow(key: &str, body_sha256: &str, bits: u32) -> Result<String, JsError> {
    aamio::solve_board_hashed(key, body_sha256, bits).map_err(refused)
}

/// sha256 over the five lines thread work is computed over.
#[wasm_bindgen(js_name = powDigest)]
pub fn pow_digest(w: &str, key: &str, body_sha256: &str, nonce: &str) -> Vec<u8> {
    aamio::pow_digest(w, key, body_sha256, nonce).to_vec()
}

/// sha256 over the four lines board work is computed over.
#[wasm_bindgen(js_name = boardPowDigest)]
pub fn board_pow_digest(key: &str, body_sha256: &str, nonce: &str) -> Vec<u8> {
    aamio::board_pow_digest(key, body_sha256, nonce).to_vec()
}

/// Leading zero bits, counted from the top bit of the first byte.
#[wasm_bindgen(js_name = zeroBits)]
pub fn zero_bits(digest: &[u8]) -> u32 {
    aamio::zero_bits(digest)
}

// ---------------------------------------------------------------------- gate --

/// The canonical text a gate_hash is taken over, from the gate as JSON text.
#[wasm_bindgen(js_name = canonicalGate)]
pub fn canonical_gate(gate_json: &str) -> Result<String, JsError> {
    Ok(aamio::canonical(&gate(gate_json)?))
}

/// sha256 hex over the canonical text.
#[wasm_bindgen(js_name = gateHash)]
pub fn gate_hash(gate_json: &str) -> Result<String, JsError> {
    Ok(aamio::gate_hash(&gate(gate_json)?))
}

// ---------------------------------------------------------------------- keys --

/// 32 bytes from crypto.getRandomValues, to keep where secrets are kept.
#[wasm_bindgen(js_name = generateSeed)]
pub fn generate_seed() -> Vec<u8> {
    Keys::generate().seed().to_vec()
}

/// The public key for a seed, as it travels: base64url, 43 characters.
#[wasm_bindgen(js_name = publicKey)]
pub fn public_key(seed: &[u8]) -> Result<String, JsError> {
    Ok(keys(seed)?.public)
}

/// A detached Ed25519 signature over the exact string, base64url.
#[wasm_bindgen]
pub fn sign(seed: &[u8], input: &str) -> Result<String, JsError> {
    Ok(keys(seed)?.sign(input))
}

/// Whether `signature` is by the holder of `key` over the exact string.
#[wasm_bindgen]
pub fn verify(key: &str, signature: &str, input: &str) -> bool {
    aamio::verify(key, signature, input)
}

/// The nacl.box.v1 envelope, as JSON text, sealed to the recipient's key, with
/// a nonce from crypto.getRandomValues.
#[wasm_bindgen]
pub fn seal(seed: &[u8], recipient_key: &str, plaintext: &[u8]) -> Result<String, JsError> {
    keys(seed)?.seal(recipient_key, plaintext).map_err(refused)
}

/// `seal` with the 24 nonce bytes brought by the caller. A nonce is used once:
/// never pass the same one twice between the same two keys.
#[wasm_bindgen(js_name = sealWithNonce)]
pub fn seal_with_nonce(seed: &[u8], recipient_key: &str, plaintext: &[u8], nonce: &[u8]) -> Result<String, JsError> {
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| JsError::new("a nonce is 24 bytes"))?;
    keys(seed)?.seal_with_nonce(recipient_key, plaintext, nonce).map_err(refused)
}

/// Opens an envelope sealed to the holder of `seed` by the holder of `senderKey`.
#[wasm_bindgen]
pub fn open(seed: &[u8], sender_key: &str, envelope: &str) -> Result<Vec<u8>, JsError> {
    keys(seed)?.open(sender_key, envelope).map_err(refused)
}
