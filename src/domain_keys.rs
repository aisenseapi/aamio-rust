//! Domain keys: which public aamio keys a website says are its own.
//!
//! A site can publish the public keys of the agents it stands behind at
//!
//! ```text
//! https://<domain>/.well-known/aamio-keys.json
//! ```
//!
//! as `{"aamio_keys": 1, "keys": [{"key": "<43 characters>", "name": "support"}]}`.
//! This module is the format and nothing else: a strict parser, the match, a
//! generator for the file, and the syntax of a domain. It opens no connection
//! and reads no address book. A library has neither the user's list of websites
//! nor a hardened read, so fetching a list is for the caller, who also says
//! which key is compared: the result says `subject_source` `supplied_key`, and
//! aamio-python and aamio-php have the whole check.
//!
//! Take the domain from your own records and never from the message being
//! checked: anyone can list their own key on their own site. A listed key says
//! that this exact site listed this key when it was read. It is not an identity,
//! an authority to act or proof that a message is true.
//!
//! serde_json keeps the last of two members of the same name without a word, so
//! it cannot hold the format's rule about duplicates, and the reader here is its
//! own. `testdata/domain_keys_vectors.json` holds what every client answers.

use std::collections::{BTreeMap, HashSet};
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

use crate::codec::sha256_hex;

pub const DOMAIN_KEYS_VERSION: i64 = 1;
pub const DOMAIN_KEYS_PATH: &str = "/.well-known/aamio-keys.json";
pub const DOMAIN_KEYS_MAX_BYTES: usize = 16384;
pub const DOMAIN_KEYS_MAX_KEYS: usize = 64;
const MAX_DEPTH: usize = 16;
const MAX_INTEGER: i64 = (1 << 53) - 1;

/// One entry on a list. The name labels and authorises nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainKey {
    pub key: String,
    pub name: Option<String>,
}

/// What a list says about one key. `status` is listed, not_listed or invalid,
/// and not_listed is no evidence of fraud: a key rotated out, the wrong name or
/// the wrong domain look the same. `document_sha256` is of the exact bytes
/// compared, for comparison and fault finding; the domain did not sign it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainMatch {
    pub status: &'static str,
    pub reason: &'static str,
    pub detail: Option<&'static str>,
    pub matched_name: Option<String>,
    pub document_sha256: Option<String>,
    pub subject_source: &'static str,
}

/// A list that is not version 1. The reason says why, without echoing the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidDomainKeys(pub &'static str);

impl fmt::Display for InvalidDomainKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid domain key list: {}", self.0)
    }
}

impl std::error::Error for InvalidDomainKeys {}

/// A public key as aamio writes it: 32 bytes, 43 characters, one spelling only.
pub fn canonical_key(value: &str) -> bool {
    if value.len() != 43 || !value.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_') {
        return false;
    }
    // The decoder refuses a last character carrying bits past the 32 bytes: it
    // decodes to the same bytes as another string, and only one is the key.
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(raw) => raw.len() == 32 && URL_SAFE_NO_PAD.encode(&raw) == value,
        Err(_) => false,
    }
}

/// A name a list can carry: 1 to 64 characters of a-z, 0-9, dot, underscore and dash.
pub fn valid_domain_key_name(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-')
}

fn label_ok(label: &str) -> bool {
    let bytes = label.as_bytes();
    let plain = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&bytes.len())
        && plain(&bytes[0])
        && plain(&bytes[bytes.len() - 1])
        && bytes.iter().all(|c| plain(c) || *c == b'-')
        && !label.starts_with("xn--")
}

/// A last label of digits or hex is an old spelling of an IPv4 address.
fn numeric_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    bytes.iter().all(u8::is_ascii_digit)
        || (bytes.len() > 2 && bytes.starts_with(b"0x") && bytes[2..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)))
}

/// The exact host a list is read from, in lowercase, or `None`. Plain ASCII names
/// of two labels or more. No port, path, IP literal, trailing dot, underscore or
/// space is trimmed into shape. Internationalised names, xn-- labels, wait until
/// every client converts them the same way. www.example.org and example.org are
/// different places, and no parent domain lends its list to a child.
pub fn normalise_domain(value: &str) -> Option<String> {
    if !value.is_ascii() {
        return None;
    }
    let domain = value.to_ascii_lowercase();
    let labels: Vec<&str> = domain.split('.').collect();
    if domain.is_empty() || domain.len() > 253 || labels.len() < 2 {
        return None;
    }
    if !labels.iter().all(|label| label_ok(label)) || numeric_label(labels[labels.len() - 1]) {
        return None;
    }
    Some(domain)
}

/// Where the list of this exact domain is, over HTTPS on the default port.
pub fn domain_keys_url(domain: &str) -> Option<String> {
    normalise_domain(domain).map(|host| format!("https://{host}{DOMAIN_KEYS_PATH}"))
}

/// The entries of a version 1 list. A duplicate key, a duplicate member name in
/// any object or one bad entry makes the whole document invalid: a list is never
/// valid with the bad part left out.
pub fn parse_domain_keys(raw: &[u8]) -> Result<Vec<DomainKey>, InvalidDomainKeys> {
    if raw.len() > DOMAIN_KEYS_MAX_BYTES {
        return Err(InvalidDomainKeys("body_limit"));
    }
    if std::str::from_utf8(raw).is_err() {
        return Err(InvalidDomainKeys("not_utf8"));
    }
    if raw.starts_with(b"\xEF\xBB\xBF") {
        return Err(InvalidDomainKeys("byte_order_mark"));
    }
    let mut reader = Reader { text: raw, at: 0 };
    let value = reader.value(1)?;
    reader.skip();
    if reader.at != raw.len() {
        return Err(InvalidDomainKeys("invalid_json"));
    }
    let Value::Object(document) = value else {
        return Err(InvalidDomainKeys("object_required"));
    };
    // An integer and nothing looser: 1.0, 1e0 and true are not the integer 1.
    if !matches!(document.get(b"aamio_keys".as_slice()), Some(Value::Integer(DOMAIN_KEYS_VERSION))) {
        return Err(InvalidDomainKeys("unsupported_version"));
    }
    let rows = match document.get(b"keys".as_slice()) {
        Some(Value::List(rows)) if rows.len() <= DOMAIN_KEYS_MAX_KEYS => rows,
        _ => return Err(InvalidDomainKeys("invalid_keys")),
    };
    let mut seen = HashSet::new();
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Object(row) = row else {
            return Err(InvalidDomainKeys("invalid_key"));
        };
        let key = match row.get(b"key".as_slice()) {
            Some(Value::Text(bytes)) => std::str::from_utf8(bytes).ok().filter(|text| canonical_key(text)),
            _ => None,
        };
        let Some(key) = key else {
            return Err(InvalidDomainKeys("invalid_key"));
        };
        if !seen.insert(key.to_string()) {
            return Err(InvalidDomainKeys("duplicate_key"));
        }
        // A name of null is a bad name and not a missing one.
        let name = match row.get(b"name".as_slice()) {
            None => None,
            Some(Value::Text(bytes)) => match std::str::from_utf8(bytes).ok().filter(|text| valid_domain_key_name(text)) {
                Some(text) => Some(text.to_string()),
                None => return Err(InvalidDomainKeys("invalid_name")),
            },
            Some(_) => return Err(InvalidDomainKeys("invalid_name")),
        };
        entries.push(DomainKey { key: key.to_string(), name });
    }
    Ok(entries)
}

/// Whether this exact document lists `key`, and under `name` when one is given.
/// The key is the caller's to choose and to answer for, which the result says as
/// `subject_source`.
pub fn match_domain_key(raw: &[u8], key: &str, name: Option<&str>) -> DomainMatch {
    let answer = |status, reason| DomainMatch { status, reason, detail: None, matched_name: None, document_sha256: None, subject_source: "supplied_key" };
    if !canonical_key(key) {
        return answer("invalid", "invalid_subject_key");
    }
    if name.is_some_and(|name| !valid_domain_key_name(name)) {
        return answer("invalid", "invalid_requested_name");
    }
    let entries = match parse_domain_keys(raw) {
        Ok(entries) => entries,
        Err(InvalidDomainKeys(detail)) => return DomainMatch { detail: Some(detail), ..answer("invalid", "invalid_document") },
    };
    let digest = sha256_hex(raw);
    for entry in entries {
        if entry.key == key && (name.is_none() || entry.name.as_deref() == name) {
            return DomainMatch { matched_name: entry.name, document_sha256: Some(digest), ..answer("listed", "key_listed") };
        }
    }
    DomainMatch { document_sha256: Some(digest), ..answer("not_listed", "key_or_name_not_listed") }
}

/// The file for a site to publish. The bytes are fixed, so every generator gives
/// the same file for the same list: two spaces of indentation, aamio_keys before
/// keys, key before name, ASCII only, and a line break at the end. An empty list
/// is allowed, since that is how a site says it lists no key, so callers ask for
/// it on purpose. A list this would refuse to read is refused here as well.
pub fn make_domain_keys(entries: &[DomainKey]) -> Result<String, InvalidDomainKeys> {
    let mut rows = Vec::with_capacity(entries.len());
    let mut seen = HashSet::new();
    for entry in entries {
        if !canonical_key(&entry.key) {
            return Err(InvalidDomainKeys("invalid_key"));
        }
        if !seen.insert(entry.key.as_str()) {
            return Err(InvalidDomainKeys("duplicate_key"));
        }
        let mut row = format!("    {{\n      \"key\": \"{}\"", entry.key);
        if let Some(name) = &entry.name {
            if !valid_domain_key_name(name) {
                return Err(InvalidDomainKeys("invalid_name"));
            }
            row.push_str(&format!(",\n      \"name\": \"{name}\""));
        }
        row.push_str("\n    }");
        rows.push(row);
    }
    if rows.len() > DOMAIN_KEYS_MAX_KEYS {
        return Err(InvalidDomainKeys("invalid_keys"));
    }
    let list = if rows.is_empty() { "[]".to_string() } else { format!("[\n{}\n  ]", rows.join(",\n")) };
    let raw = format!("{{\n  \"aamio_keys\": {DOMAIN_KEYS_VERSION},\n  \"keys\": {list}\n}}\n");
    parse_domain_keys(raw.as_bytes())?;
    Ok(raw)
}

/// A JSON value, with strings as bytes: a lone surrogate escape has no place in a
/// `String`, and two different ones must not become one name.
enum Value {
    Object(BTreeMap<Vec<u8>, Value>),
    List(Vec<Value>),
    Text(Vec<u8>),
    Integer(i64),
    Other,
}

struct Reader<'a> {
    text: &'a [u8],
    at: usize,
}

const BAD_JSON: InvalidDomainKeys = InvalidDomainKeys("invalid_json");

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.at).copied()
    }

    fn skip(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.at += 1;
        }
    }

    fn value(&mut self, level: usize) -> Result<Value, InvalidDomainKeys> {
        self.skip();
        match self.peek() {
            Some(b'{') => self.members(level),
            Some(b'[') => self.rows(level),
            Some(b'"') => Ok(Value::Text(self.string()?)),
            Some(_) => {
                for word in [&b"true"[..], &b"false"[..], &b"null"[..]] {
                    if self.text[self.at..].starts_with(word) {
                        self.at += word.len();
                        return Ok(Value::Other);
                    }
                }
                self.number()
            }
            None => Err(BAD_JSON),
        }
    }

    fn members(&mut self, level: usize) -> Result<Value, InvalidDomainKeys> {
        if level > MAX_DEPTH {
            return Err(InvalidDomainKeys("depth_limit"));
        }
        self.at += 1;
        let mut found = BTreeMap::new();
        self.skip();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Object(found));
        }
        loop {
            self.skip();
            if self.peek() != Some(b'"') {
                return Err(BAD_JSON);
            }
            let name = self.string()?;
            if found.contains_key(&name) {
                return Err(InvalidDomainKeys("duplicate_member"));
            }
            self.skip();
            if self.peek() != Some(b':') {
                return Err(BAD_JSON);
            }
            self.at += 1;
            let value = self.value(level + 1)?;
            found.insert(name, value);
            self.skip();
            let next = self.peek();
            self.at += 1;
            match next {
                Some(b'}') => return Ok(Value::Object(found)),
                Some(b',') => {}
                _ => return Err(BAD_JSON),
            }
        }
    }

    fn rows(&mut self, level: usize) -> Result<Value, InvalidDomainKeys> {
        if level > MAX_DEPTH {
            return Err(InvalidDomainKeys("depth_limit"));
        }
        self.at += 1;
        let mut found = Vec::new();
        self.skip();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::List(found));
        }
        loop {
            found.push(self.value(level + 1)?);
            self.skip();
            let next = self.peek();
            self.at += 1;
            match next {
                Some(b']') => return Ok(Value::List(found)),
                Some(b',') => {}
                _ => return Err(BAD_JSON),
            }
        }
    }

    /// Two surrogate escapes in a row are one character, the same bytes as the
    /// character written out, and one on its own stays what it is.
    fn string(&mut self) -> Result<Vec<u8>, InvalidDomainKeys> {
        self.at += 1;
        let mut out = Vec::new();
        loop {
            let c = self.peek().ok_or(BAD_JSON)?;
            self.at += 1;
            match c {
                b'"' => return Ok(out),
                0x00..=0x1F => return Err(BAD_JSON),
                b'\\' => {}
                _ => {
                    out.push(c);
                    continue;
                }
            }
            let escape = self.peek().ok_or(BAD_JSON)?;
            self.at += 1;
            match escape {
                b'"' | b'\\' | b'/' => out.push(escape),
                b'b' => out.push(0x08),
                b'f' => out.push(0x0C),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'u' => {
                    let mut unit = self.unit()?;
                    if (0xD800..=0xDBFF).contains(&unit) && self.text[self.at..].starts_with(b"\\u") {
                        let mark = self.at;
                        self.at += 2;
                        let low = self.unit()?;
                        if (0xDC00..=0xDFFF).contains(&low) {
                            unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                        } else {
                            self.at = mark;
                        }
                    }
                    push_code_point(&mut out, unit);
                }
                _ => return Err(BAD_JSON),
            }
        }
    }

    /// The four hexadecimal digits of a \u escape.
    fn unit(&mut self) -> Result<u32, InvalidDomainKeys> {
        let digits = self.text.get(self.at..self.at + 4).ok_or(BAD_JSON)?;
        let mut value = 0;
        for c in digits {
            value = value << 4 | (*c as char).to_digit(16).ok_or(BAD_JSON)?;
        }
        self.at += 4;
        Ok(value)
    }

    fn digits(&mut self) -> usize {
        let from = self.at;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.at += 1;
        }
        self.at - from
    }

    fn number(&mut self) -> Result<Value, InvalidDomainKeys> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        if self.peek() == Some(b'0') {
            self.at += 1;
        } else if self.digits() == 0 {
            return Err(BAD_JSON);
        }
        let mut float = false;
        // A point or an exponent with no digit is not part of the number, and
        // what follows the number then fails as what it is.
        if self.peek() == Some(b'.') && matches!(self.text.get(self.at + 1), Some(b'0'..=b'9')) {
            self.at += 1;
            self.digits();
            float = true;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let mark = self.at;
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            if self.digits() == 0 {
                self.at = mark;
            } else {
                float = true;
            }
        }
        let token = std::str::from_utf8(&self.text[start..self.at]).map_err(|_| BAD_JSON)?;
        if float {
            return match token.parse::<f64>() {
                Ok(value) if value.is_finite() => Ok(Value::Other),
                _ => Err(InvalidDomainKeys("non_finite_number")),
            };
        }
        match token.parse::<i64>() {
            Ok(value) if (-MAX_INTEGER..=MAX_INTEGER).contains(&value) => Ok(Value::Integer(value)),
            _ => Err(InvalidDomainKeys("integer_range")),
        }
    }
}

/// UTF-8, a lone surrogate in the same three-byte form, which `char` cannot hold.
fn push_code_point(out: &mut Vec<u8>, point: u32) {
    match point {
        0..=0x7F => out.push(point as u8),
        0x80..=0x7FF => out.extend([0xC0 | (point >> 6) as u8, 0x80 | (point & 0x3F) as u8]),
        0x800..=0xFFFF => out.extend([0xE0 | (point >> 12) as u8, 0x80 | ((point >> 6) & 0x3F) as u8, 0x80 | (point & 0x3F) as u8]),
        _ => out.extend([0xF0 | (point >> 18) as u8, 0x80 | ((point >> 12) & 0x3F) as u8, 0x80 | ((point >> 6) & 0x3F) as u8, 0x80 | (point & 0x3F) as u8]),
    }
}
