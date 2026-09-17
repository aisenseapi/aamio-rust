//! One Ed25519 identity: signs what leaves, seals to partners, opens what
//! arrives. The X25519 pair used for sealing is derived from the Ed25519 pair
//! the way libsodium does it, so a box sealed here opens in the other clients,
//! and theirs open here.

use crypto_box::aead::Aead;
use crypto_box::{Nonce, PublicKey, SalsaBox, SecretKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::codec::{b64url, is_key, sha256, sha256_hex, unb64url};

/// The name a sealed body carries in its `e2ee` field.
pub const ENVELOPE: &str = "nacl.box.v1";

/// One identity.
#[derive(Clone)]
pub struct Keys {
    seed: [u8; 32],
    signing: SigningKey,
    curve_secret: [u8; 32],
    /// The key as it travels: base64url, 43 characters.
    pub public: String,
    /// sha256 hex over the raw 32 bytes.
    pub hash: String,
    /// The first 8 characters of `hash`.
    pub hash_prefix: String,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    e2ee: String,
    to: String,
    nonce: String,
    ct: String,
}

impl Keys {
    /// A fresh identity from the system's CSPRNG.
    pub fn generate() -> Keys {
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Keys::from_seed(seed)
    }

    /// Rebuilds an identity from its 32 seed bytes.
    pub fn from_seed(seed: [u8; 32]) -> Keys {
        let signing = SigningKey::from_bytes(&seed);
        let public_raw = signing.verifying_key().to_bytes();
        let hash = hex::encode(sha256(&public_raw));
        Keys {
            seed,
            // libsodium: crypto_sign_ed25519_sk_to_curve25519 is sha512(seed)[..32], clamped.
            curve_secret: signing.to_scalar_bytes(),
            signing,
            public: b64url(&public_raw),
            hash_prefix: hash[..8].to_string(),
            hash,
        }
    }

    /// `from_seed` over a hex string.
    pub fn from_seed_hex(text: &str) -> Result<Keys, String> {
        let bytes = hex::decode(text).map_err(|e| e.to_string())?;
        let seed: [u8; 32] = bytes.try_into().map_err(|_| "a seed is 32 bytes".to_string())?;
        Ok(Keys::from_seed(seed))
    }

    /// The 32 bytes to keep under a file with mode 600, and nowhere else.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }

    /// A detached signature over the exact string, base64url.
    pub fn sign(&self, input: &str) -> String {
        b64url(&self.signing.sign(input.as_bytes()).to_bytes())
    }

    /// The envelope, as JSON text, sealed to the recipient's key. The recipient opens it with our public key.
    pub fn seal(&self, recipient_key: &str, plaintext: &[u8]) -> Result<String, String> {
        let mut nonce_bytes = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        self.seal_with_nonce(recipient_key, plaintext, nonce_bytes)
    }

    /// `seal` with the nonce brought by the caller: for a host that has its own
    /// source of randomness, and for reproducing a vector byte for byte. A nonce
    /// is used once: never pass the same one twice between the same two keys.
    pub fn seal_with_nonce(&self, recipient_key: &str, plaintext: &[u8], nonce_bytes: [u8; 24]) -> Result<String, String> {
        let peer = curve_public(recipient_key)?;
        let nonce = Nonce::from(nonce_bytes);
        let salsa = SalsaBox::new(&PublicKey::from(peer), &SecretKey::from(self.curve_secret));
        let ct = salsa.encrypt(&nonce, plaintext).map_err(|_| "sealing failed".to_string())?;
        let envelope = Envelope { e2ee: ENVELOPE.to_string(), to: hash_prefix_of(recipient_key)?, nonce: b64url(&nonce_bytes), ct: b64url(&ct) };
        serde_json::to_string(&envelope).map_err(|e| e.to_string())
    }

    /// Opens an envelope sealed to us by the holder of `sender_key`.
    pub fn open(&self, sender_key: &str, envelope_text: &str) -> Result<Vec<u8>, String> {
        let envelope: Envelope = serde_json::from_str(envelope_text).map_err(|_| "not an envelope".to_string())?;
        if envelope.e2ee != ENVELOPE {
            return Err("not an envelope".to_string());
        }
        if envelope.to != self.hash_prefix {
            return Err(format!("this envelope is sealed to {}, not to {}", envelope.to, self.hash_prefix));
        }
        let peer = curve_public(sender_key)?;
        let nonce_bytes: [u8; 24] = unb64url(&envelope.nonce).map_err(|e| e.to_string())?.try_into().map_err(|_| "the nonce is not 24 bytes".to_string())?;
        let ct = unb64url(&envelope.ct).map_err(|e| e.to_string())?;
        let salsa = SalsaBox::new(&PublicKey::from(peer), &SecretKey::from(self.curve_secret));
        salsa.decrypt(&Nonce::from(nonce_bytes), ct.as_slice()).map_err(|_| "the envelope does not open with this key pair".to_string())
    }
}

/// Checks a signature by the holder of `key` over the exact string.
pub fn verify(key: &str, signature: &str, input: &str) -> bool {
    if !is_key(key) {
        return false;
    }
    let Ok(raw) = unb64url(key) else { return false };
    let Ok(raw): Result<[u8; 32], _> = raw.try_into() else { return false };
    let Ok(verifying) = VerifyingKey::from_bytes(&raw) else { return false };
    let Ok(sig) = unb64url(signature) else { return false };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else { return false };
    verifying.verify(input.as_bytes(), &Signature::from_bytes(&sig)).is_ok()
}

/// The X25519 public key derived from an Ed25519 public key, the way libsodium's
/// `crypto_sign_ed25519_pk_to_curve25519` does.
pub fn curve_public(key: &str) -> Result<[u8; 32], String> {
    if !is_key(key) {
        return Err("not a base64url Ed25519 public key of 32 bytes".to_string());
    }
    let raw: [u8; 32] = unb64url(key).map_err(|e| e.to_string())?.try_into().map_err(|_| "not 32 bytes".to_string())?;
    let verifying = VerifyingKey::from_bytes(&raw).map_err(|_| "not a point on the curve".to_string())?;
    Ok(verifying.to_montgomery().to_bytes())
}

/// The first 8 hex characters of sha256 over a key's raw bytes.
pub fn hash_prefix_of(key: &str) -> Result<String, String> {
    let raw = unb64url(key).map_err(|e| e.to_string())?;
    Ok(hex::encode(sha256(&raw))[..8].to_string())
}

/// Whether a body claims to be a sealed envelope.
/// The recipient an envelope names, the first 8 hex of sha256 over their
/// public key, or None when the body does not say. It answers the question a
/// reader would otherwise guess at: is this sealed to me.
pub fn envelope_to(body: &str) -> Option<String> {
    match serde_json::from_str::<Envelope>(body) {
        Ok(e) if e.e2ee == ENVELOPE && !e.to.is_empty() => Some(e.to),
        _ => None,
    }
}

pub fn is_envelope(body: &str) -> bool {
    match serde_json::from_str::<Envelope>(body) {
        Ok(e) => e.e2ee == ENVELOPE && !e.nonce.is_empty() && !e.ct.is_empty(),
        Err(_) => false,
    }
}

/// What a thread write is signed over.
pub fn thread_signing_input(w: &str, body: &[u8]) -> String {
    format!("aamio-v1\n{}\n{}", w, sha256_hex(body))
}

/// What a presence publish is signed over.
pub fn presence_signing_input(key: &str, body: &[u8]) -> String {
    format!("aamio-presence-v1\n{}\n{}", key, sha256_hex(body))
}

/// What a presence delete is signed over.
pub fn presence_delete_signing_input(key: &str, body: &[u8]) -> String {
    format!("aamio-presence-delete-v1\n{}\n{}", key, sha256_hex(body))
}

/// What a board post is signed over.
pub fn board_signing_input(key: &str, body: &[u8]) -> String {
    format!("aamio-board-v1\n{}\n{}", key, sha256_hex(body))
}

/// What a board withdrawal is signed over.
pub fn board_delete_signing_input(id: &str, body: &[u8]) -> String {
    format!("aamio-board-delete-v1\n{}\n{}", id, sha256_hex(body))
}
