//! The vectors every client that takes the format up shares, the same file
//! aamio-python keeps.

use aamio::domain_keys::{
    canonical_key, domain_keys_url, make_domain_keys, match_domain_key, normalise_domain, parse_domain_keys, DomainKey, InvalidDomainKeys,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::Value;

const VECTORS: &str = include_str!("../testdata/domain_keys_vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).unwrap()
}

fn entries(row: &Value) -> Vec<DomainKey> {
    row["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| DomainKey { key: entry["key"].as_str().unwrap().to_string(), name: entry["name"].as_str().map(str::to_string) })
        .collect()
}

#[test]
fn the_vectors_are_the_shared_ones() {
    let Ok(there) = std::fs::read_to_string("../aamio-python/tests/domain_keys_vectors.json") else {
        return;
    };
    assert!(there == VECTORS, "testdata/domain_keys_vectors.json differs from the one aamio-python keeps");
}

#[test]
fn documents() {
    for row in vectors()["documents"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let raw = match row["text"].as_str() {
            Some(text) => text.as_bytes().to_vec(),
            None => STANDARD.decode(row["b64"].as_str().unwrap()).unwrap(),
        };
        let parsed = parse_domain_keys(&raw);
        if row["valid"].as_bool().unwrap() {
            assert_eq!(parsed.map(|entries| entries.len() as u64), Ok(row["keys"].as_u64().unwrap()), "{case}");
        } else {
            assert!(parsed.is_err(), "{case}");
        }
    }
}

#[test]
fn matches() {
    for row in vectors()["matches"].as_array().unwrap() {
        let case = row["case"].as_str().unwrap();
        let found = match_domain_key(row["text"].as_str().unwrap().as_bytes(), row["key"].as_str().unwrap(), row["name"].as_str());
        assert_eq!(found.status, row["status"].as_str().unwrap(), "{case}");
        if let Some(reason) = row["reason"].as_str() {
            assert_eq!(found.reason, reason, "{case}");
        }
        if row.get("matched_name").is_some() {
            assert_eq!(found.matched_name.as_deref(), row["matched_name"].as_str(), "{case}");
        }
        assert_eq!(found.document_sha256.as_deref(), row["document_sha256"].as_str(), "{case}");
        assert_eq!(found.subject_source, "supplied_key", "the key was the caller's, and the result has to say so");
    }
}

#[test]
fn domains() {
    let v = vectors();
    for pair in v["domains"]["valid"].as_array().unwrap() {
        assert_eq!(normalise_domain(pair[0].as_str().unwrap()).as_deref(), pair[1].as_str());
    }
    for domain in v["domains"]["invalid"].as_array().unwrap() {
        assert_eq!(normalise_domain(domain.as_str().unwrap()), None, "{domain}");
    }
    assert_eq!(domain_keys_url("Example.ORG").as_deref(), Some("https://example.org/.well-known/aamio-keys.json"));
    assert_eq!(domain_keys_url("https://example.org"), None);
}

#[test]
fn generated() {
    let v = vectors();
    for row in v["generated"].as_array().unwrap() {
        assert_eq!(make_domain_keys(&entries(row)).unwrap(), row["text"].as_str().unwrap());
    }
    for row in v["refused"].as_array().unwrap() {
        assert!(make_domain_keys(&entries(row)).is_err(), "{}", row["case"]);
    }
}

#[test]
fn an_invalid_document_says_why_without_its_content() {
    let found = match_domain_key(br#"{"aamio_keys":2,"keys":[],"x":"secret text"}"#, "29VTeOqp8srcy1SyPZ3NtHy9XBnLf4h7D2LDrCzo7S4", None);
    assert_eq!((found.status, found.reason, found.detail), ("invalid", "invalid_document", Some("unsupported_version")));
    assert_eq!(InvalidDomainKeys("depth_limit").to_string(), "invalid domain key list: depth_limit");
    assert!(canonical_key("29VTeOqp8srcy1SyPZ3NtHy9XBnLf4h7D2LDrCzo7S4") && !canonical_key("CogegzJHFnSuSTOXEiM5bQ98Dt6qOS7VeFXN8Azj0bl"));
}
