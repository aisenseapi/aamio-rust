//! The encodings every other module shares: base64url without padding for
//! keys, signatures and envelopes; lowercase base32 for write addresses;
//! sha256 in hex over exact bytes.

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use sha2::{Digest, Sha256};

/// base64url without padding.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url without padding, and accepts standard base64 with or
/// without padding too, as the service does.
pub fn unb64url(text: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let trimmed = text.trim_end_matches('=');
    if trimmed.contains('+') || trimmed.contains('/') {
        STANDARD_NO_PAD.decode(trimmed)
    } else {
        URL_SAFE_NO_PAD.decode(trimmed)
    }
}

/// Lowercase hex of sha256 over the exact bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// sha256 as raw bytes.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// RFC 4648 base32, lowercased, without padding.
pub fn base32(bytes: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(bytes).to_lowercase()
}

/// Whether `s` has the shape of a public key: 43 characters of base64url.
pub fn is_key(s: &str) -> bool {
    s.len() == 43 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
