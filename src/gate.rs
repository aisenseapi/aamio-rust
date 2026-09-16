//! Gate from the writer's side: the canonical text and hash of a gate, the
//! proof of work, and the plan a client follows before writing to an inbox
//! that sets conditions. The ceilings are the service's own, so an inbox run
//! by a stranger can never make this client spend more CPU than aamio lets any
//! inbox ask for.

use serde_json::{Map, Value};

use crate::codec::{sha256, sha256_hex};

/// The most work an inbox may require.
pub const REQUIRE_MAX_BITS: u32 = 20;
/// The most work a client does without asking.
pub const ADVISE_MAX_BITS: u32 = 18;

// ----------------------------------------------------------------- canonical --

/// The canonical text a gate_hash is taken over: keys sorted by their UTF-8
/// bytes at every level, no whitespace, integers as integers, an empty object
/// as `{}`, empty buckets removed, strings escaped only where JSON requires it.
/// serde_json's object is a sorted map and its writer escapes exactly the
/// quote, the backslash and the control characters, so the encoding is its own.
pub fn canonical(gate: &Value) -> String {
    let mut pruned = match gate {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    for bucket in ["require", "advise"] {
        if matches!(pruned.get(bucket), Some(Value::Object(m)) if m.is_empty()) {
            pruned.remove(bucket);
        }
    }
    serde_json::to_string(&Value::Object(pruned)).expect("a map of JSON values serialises")
}

/// sha256 hex over the canonical text.
pub fn gate_hash(gate: &Value) -> String {
    sha256_hex(canonical(gate).as_bytes())
}

// ---------------------------------------------------------------------- work --

/// What thread work is computed over. `key` is the X-Key exactly as sent, or
/// empty for an unsigned message, so two line breaks meet.
pub fn pow_input(w: &str, key: &str, body_sha256: &str, nonce: &str) -> String {
    format!("aamio-pow-v1\n{}\n{}\n{}\n{}", w, key, body_sha256, nonce)
}

/// sha256 over `pow_input`.
pub fn pow_digest(w: &str, key: &str, body_sha256: &str, nonce: &str) -> [u8; 32] {
    sha256(pow_input(w, key, body_sha256, nonce).as_bytes())
}

/// What board work is computed over: no address, a post is not to a thread.
pub fn board_pow_input(key: &str, body_sha256: &str, nonce: &str) -> String {
    format!("aamio-board-pow-v1\n{}\n{}\n{}", key, body_sha256, nonce)
}

/// sha256 over `board_pow_input`.
pub fn board_pow_digest(key: &str, body_sha256: &str, nonce: &str) -> [u8; 32] {
    sha256(board_pow_input(key, body_sha256, nonce).as_bytes())
}

/// Leading zero bits, counted from the top bit of the first byte.
pub fn zero_bits(digest: &[u8]) -> u32 {
    let mut bits = 0;
    for &byte in digest {
        if byte == 0 {
            bits += 8;
            continue;
        }
        bits += byte.leading_zeros();
        break;
    }
    bits
}

/// Whether `s` is a valid X-Work value: 1 to 64 characters of `[A-Za-z0-9_-]`.
pub fn is_nonce(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// The first nonce, counting from 0, whose thread digest reaches `bits`.
pub fn solve(w: &str, key: &str, body: &[u8], bits: u32) -> Result<String, String> {
    if bits > REQUIRE_MAX_BITS {
        return Err(format!("work is 0 to {} bits", REQUIRE_MAX_BITS));
    }
    let prefix = format!("aamio-pow-v1\n{}\n{}\n{}\n", w, key, sha256_hex(body));
    Ok(first_nonce(&prefix, bits))
}

/// The first nonce whose board digest reaches `bits`, over the exact text posted.
pub fn solve_board(key: &str, body: &[u8], bits: u32) -> Result<String, String> {
    if bits > REQUIRE_MAX_BITS {
        return Err(format!("work is 0 to {} bits", REQUIRE_MAX_BITS));
    }
    let prefix = format!("aamio-board-pow-v1\n{}\n{}\n", key, sha256_hex(body));
    Ok(first_nonce(&prefix, bits))
}

fn first_nonce(prefix: &str, bits: u32) -> String {
    let mut n: u64 = 0;
    loop {
        let candidate = n.to_string();
        if zero_bits(&sha256(format!("{}{}", prefix, candidate).as_bytes())) >= bits {
            return candidate;
        }
        n += 1;
    }
}

// ---------------------------------------------------------------------- plan --

/// What to do about an inbox's gate before writing.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    /// Bits to work for, `None` for none.
    pub bits: Option<u32>,
    /// The reason the send must not happen, when it must not.
    pub stop: Option<String>,
    /// What was passed over.
    pub notes: Vec<String>,
}

fn bits_of(condition: &Value) -> u32 {
    condition.get("bits").and_then(Value::as_u64).unwrap_or(0) as u32
}

/// Reads a gate and decides. `None` or an empty gate is nothing to do.
pub fn plan(gate: Option<&Value>) -> Plan {
    let mut plan = Plan::default();
    let Some(Value::Object(gate)) = gate else { return plan };
    if gate.is_empty() {
        return plan;
    }
    let known = ["pow", "per_key", "write_until"];
    if let Some(Value::Object(require)) = gate.get("require") {
        for (condition, value) in require {
            if !known.contains(&condition.as_str()) {
                plan.stop = Some(format!("the inbox requires \"{}\", which this client does not know; nothing was sent", condition));
                return plan;
            }
            if condition == "pow" {
                let bits = bits_of(value);
                if bits > REQUIRE_MAX_BITS {
                    plan.stop = Some(format!("the inbox requires {} bits of work, above the {} aamio lets an inbox ask for; nothing was sent", bits, REQUIRE_MAX_BITS));
                    return plan;
                }
                plan.bits = Some(plan.bits.unwrap_or(0).max(bits));
            }
        }
    }
    if let Some(Value::Object(advise)) = gate.get("advise") {
        for (condition, value) in advise {
            if condition != "pow" {
                plan.notes.push(format!("the inbox advises \"{}\", which this client does not know, and it was passed over", condition));
                continue;
            }
            let bits = bits_of(value);
            if bits > ADVISE_MAX_BITS {
                plan.notes.push(format!("the inbox advises {} bits of work, above the {} a client does without asking, and it was passed over", bits, ADVISE_MAX_BITS));
                continue;
            }
            plan.bits = Some(plan.bits.unwrap_or(0).max(bits));
        }
    }
    plan
}
