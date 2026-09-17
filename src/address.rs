//! The read key and the write address. The read key is made here, from a
//! CSPRNG, and travels only in the X-Read header. The write address is the
//! first 20 characters of the lowercase base32 of sha256(id), the same on
//! every client and on the service.

use rand::Rng;

use crate::codec::{base32, sha256};

const ID_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

/// A read key: 26 characters of `[a-z0-9]`.
pub fn new_id() -> String {
    new_id_length(26).expect("26 is within 20 to 64")
}

/// A read key of the given length, 20 to 64.
pub fn new_id_length(length: usize) -> Result<String, String> {
    if !(20..=64).contains(&length) {
        return Err("an id is 20 to 64 characters".to_string());
    }
    let mut rng = rand::rngs::OsRng;
    Ok((0..length).map(|_| ID_ALPHABET[rng.gen_range(0..ID_ALPHABET.len())] as char).collect())
}

/// Whether `s` has the shape of a read key.
pub fn is_id(s: &str) -> bool {
    (20..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Whether `s` has the shape of a write address.
pub fn is_w(s: &str) -> bool {
    s.len() == 20 && s.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
}

/// The write address of a read key.
pub fn w(id: &str) -> Result<String, String> {
    if !is_id(id) {
        return Err("an id is 20 to 64 characters of a-z and 0-9".to_string());
    }
    Ok(base32(&sha256(id.as_bytes()))[..20].to_string())
}

/// A scope key, the read capability of a scope: 26 characters of `[a-z0-9]`
/// from the OS CSPRNG, like a read key. The board checks only its form, so a
/// key someone chose is a key someone else can guess.
pub fn new_scope_key() -> String {
    new_id_length(26).expect("26 is within 20 to 64")
}

/// Whether `s` has the shape of a scope key: 26 to 64 characters of `[a-z0-9]`.
pub fn is_scope_key(s: &str) -> bool {
    (26..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// The write capability of a scope: the first 20 characters of the lowercase
/// base32 of sha256("aamio-scope-v1\n" + key). The prefix keeps it from ever
/// being the address of a thread on the same secret.
pub fn scope_address(scope_key: &str) -> Result<String, String> {
    if !is_scope_key(scope_key) {
        return Err("a scope key is 26 to 64 characters of a-z and 0-9, never the 20 character address".to_string());
    }
    Ok(base32(&sha256(format!("aamio-scope-v1\n{}", scope_key).as_bytes()))[..20].to_string())
}
