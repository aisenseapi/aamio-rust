//! Gate from the writer's side: the canonical text and hash of a gate, the
//! proof of work, and the plan a client follows before writing to an inbox
//! that sets conditions. The ceilings are the service's own, so an inbox run
//! by a stranger can never make this client spend more CPU than aamio lets any
//! inbox ask for. 32 bits is for an inbox that means to meet only writers with
//! real compute, so the plan weighs the work against the time the inbox has
//! left and says no before it starts, rather than learning it from a 410.

use std::sync::OnceLock;
use std::time::Instant;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::codec::{sha256, sha256_hex};

/// The most work an inbox may require.
pub const REQUIRE_MAX_BITS: u32 = 32;
/// Below this the work is a second or so, and not worth timing first.
const ESTIMATE_FROM_BITS: u32 = 17;
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
    solve_hashed(w, key, &sha256_hex(body), bits)
}

/// `solve` for a caller that already holds the body's sha256 as lowercase hex,
/// which a client that signs does: the signing input is taken over the same hash.
pub fn solve_hashed(w: &str, key: &str, body_sha256: &str, bits: u32) -> Result<String, String> {
    if bits > REQUIRE_MAX_BITS {
        return Err(format!("work is 0 to {} bits", REQUIRE_MAX_BITS));
    }
    Ok(first_nonce(&format!("aamio-pow-v1\n{}\n{}\n{}\n", w, key, body_sha256), bits))
}

/// `solve` with a deadline: `Ok(None)` when it passes first. Past the life of
/// the inbox the work buys nothing, and 32 bits can run for hours.
pub fn solve_until(w: &str, key: &str, body: &[u8], bits: u32, deadline: Option<Instant>) -> Result<Option<String>, String> {
    if bits > REQUIRE_MAX_BITS {
        return Err(format!("work is 0 to {} bits", REQUIRE_MAX_BITS));
    }
    Ok(first_nonce_until(&format!("aamio-pow-v1\n{}\n{}\n{}\n", w, key, sha256_hex(body)), bits, deadline))
}

static RATE: OnceLock<f64> = OnceLock::new();

/// Attempts a second the search makes on this machine, timed once and kept.
/// The estimate before long work is only as good as this number, so it is the
/// search's own loop that is timed, for a quarter of a second.
pub fn hash_rate() -> f64 {
    *RATE.get_or_init(|| {
        let base = Sha256::new_with_prefix(format!("aamio-pow-v1\ncalibration\n\n{}\n", "0".repeat(64)).as_bytes());
        let mut digits = [0u8; 20];
        let mut count: u64 = 0;
        let start = Instant::now();
        while start.elapsed().as_secs_f64() < 0.25 {
            for _ in 0..4096 {
                let at = write_decimal(count, &mut digits);
                let mut hasher = base.clone();
                hasher.update(&digits[at..]);
                std::hint::black_box(zero_bits(&hasher.finalize()));
                count += 1;
            }
        }
        count as f64 / start.elapsed().as_secs_f64()
    })
}

/// How long `bits` of work takes here on average. A lottery: one in a
/// hundred takes about 4.6 times as long.
pub fn expected_seconds(bits: u32) -> f64 {
    2f64.powi(bits as i32) / hash_rate()
}

/// A time in seconds as a person would say it.
pub fn describe_seconds(seconds: f64) -> String {
    if seconds < 90.0 {
        format!("{} seconds", seconds.round().max(1.0) as u64)
    } else if seconds < 5400.0 {
        format!("{} minutes", (seconds / 60.0).round() as u64)
    } else {
        format!("{:.1} hours", seconds / 3600.0)
    }
}

/// The first nonce whose board digest reaches `bits`, over the exact text posted.
pub fn solve_board(key: &str, body: &[u8], bits: u32) -> Result<String, String> {
    solve_board_hashed(key, &sha256_hex(body), bits)
}

/// `solve_board` for a caller that already holds the body's sha256.
pub fn solve_board_hashed(key: &str, body_sha256: &str, bits: u32) -> Result<String, String> {
    if bits > REQUIRE_MAX_BITS {
        return Err(format!("work is 0 to {} bits", REQUIRE_MAX_BITS));
    }
    Ok(first_nonce(&format!("aamio-board-pow-v1\n{}\n{}\n", key, body_sha256), bits))
}

/// Counts from 0, so every client finds the same nonce. The prefix is hashed
/// once and its state reused, so a candidate costs the last block alone, and
/// the digits are written into a buffer on the stack: a million candidates
/// allocate nothing. The whole search is one call, which is what makes it
/// worth compiling to WebAssembly: a host crosses into it once, not per hash.
fn first_nonce(prefix: &str, bits: u32) -> String {
    first_nonce_until(prefix, bits, None).expect("without a deadline the search ends only with a nonce")
}

/// `first_nonce`, stopping when `deadline` passes. The clock is looked at every
/// 65536 candidates, and never without a deadline, so the search compiled to
/// WebAssembly, where there is no clock to read, never asks for one.
fn first_nonce_until(prefix: &str, bits: u32, deadline: Option<Instant>) -> Option<String> {
    let base = Sha256::new_with_prefix(prefix.as_bytes());
    let mut digits = [0u8; 20];
    let mut n: u64 = 0;
    loop {
        let start = write_decimal(n, &mut digits);
        let mut hasher = base.clone();
        hasher.update(&digits[start..]);
        if zero_bits(&hasher.finalize()) >= bits {
            return Some(String::from_utf8_lossy(&digits[start..]).into_owned());
        }
        n += 1;
        if let Some(deadline) = deadline {
            if n & 0xFFFF == 0 && Instant::now() > deadline {
                return None;
            }
        }
    }
}

/// `n` in decimal at the end of `out`; returns where it starts.
fn write_decimal(mut n: u64, out: &mut [u8; 20]) -> usize {
    let mut i = out.len();
    loop {
        i -= 1;
        out[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return i;
        }
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
    /// How long the required work takes here, when a time left was given.
    pub expected_seconds: f64,
}

fn bits_of(condition: &Value) -> u32 {
    condition.get("bits").and_then(Value::as_u64).unwrap_or(0) as u32
}

/// Reads a gate and decides. `None` or an empty gate is nothing to do.
pub fn plan(gate: Option<&Value>) -> Plan {
    plan_within(gate, None)
}

/// `plan`, weighed against `seconds_left`, how long the inbox still takes
/// writes, from X-Seconds-Left on its gate. Work that would not be done by
/// then is not started.
pub fn plan_within(gate: Option<&Value>, seconds_left: Option<f64>) -> Plan {
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
                if let Some(left) = seconds_left {
                    let expected = if bits >= ESTIMATE_FROM_BITS { expected_seconds(bits) } else { 0.0 };
                    if expected > left {
                        plan.stop = Some(format!("the inbox requires {} bits of work, which takes about {} on this machine, and it takes writes for {} more. The work would not be done before it closes, so it was not started and nothing was sent. Ask the owner for a longer inbox or less work, or send from a machine with more compute", bits, describe_seconds(expected), describe_seconds(left)));
                        return plan;
                    }
                    plan.expected_seconds = expected;
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
