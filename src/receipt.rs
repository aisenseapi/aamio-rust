//! A receipt says that these messages passed through this thread, with their
//! hashes, times and signer keys, and one root over all of it. This
//! recomputes the root from the lines, so a client trusts a number it can
//! check rather than one it was handed.

use serde::{Deserialize, Serialize};

use crate::codec::sha256_hex;

/// One line of a receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptMessage {
    pub seq: i64,
    pub at: i64,
    pub sha256: String,
    #[serde(default)]
    pub from: Option<String>,
}

/// What `GET /{w}/receipt` answers: hashes, times, keys and one root, no content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub schema: String,
    pub w: String,
    pub created_at: i64,
    pub expire_at: i64,
    pub count: i64,
    pub bytes: i64,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub gate_hash: Option<String>,
    pub messages: Vec<ReceiptMessage>,
    #[serde(default)]
    pub keys: Vec<String>,
    pub root: String,
    #[serde(default)]
    pub commitment: String,
    #[serde(default)]
    pub issued_at: i64,
    #[serde(default)]
    pub how: String,
}

/// root = sha256 of the lines "seq<TAB>at<TAB>sha256<TAB>from-or-dash<LF>" in seq order.
pub fn root(messages: &[ReceiptMessage]) -> String {
    let mut sorted: Vec<&ReceiptMessage> = messages.iter().collect();
    sorted.sort_by_key(|m| m.seq);
    let mut lines = String::new();
    for m in sorted {
        let from = m.from.as_deref().filter(|f| !f.is_empty()).unwrap_or("-");
        lines.push_str(&format!("{}\t{}\t{}\t{}\n", m.seq, m.at, m.sha256, from));
    }
    sha256_hex(lines.as_bytes())
}

/// What a client can say about a receipt on its own. `local_hashes_match` is
/// `None` when the receipt counts more messages than the client holds, which
/// is a receipt taken later, not a failure.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub root_adds_up: bool,
    pub commitment_matches: bool,
    pub local_hashes_match: Option<bool>,
}

/// Recomputes and compares. `local_hashes` are the sha256 values this process saw, in seq order.
pub fn verify_receipt(receipt: &Receipt, local_hashes: Option<&[String]>) -> Check {
    let computed = root(&receipt.messages);
    let mut check = Check {
        root_adds_up: computed == receipt.root,
        commitment_matches: receipt.commitment == format!("sha256:{}", receipt.root),
        local_hashes_match: None,
    };
    if let Some(local) = local_hashes {
        if receipt.messages.len() < local.len() {
            check.local_hashes_match = Some(false);
        } else if receipt.messages.len() == local.len() {
            let mut sorted: Vec<&ReceiptMessage> = receipt.messages.iter().collect();
            sorted.sort_by_key(|m| m.seq);
            check.local_hashes_match = Some(sorted.iter().zip(local).all(|(m, h)| &m.sha256 == h));
        }
    }
    check
}
