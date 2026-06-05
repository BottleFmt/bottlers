//! JSON encoding tests (draft §7), including CBOR<->JSON cross-format fidelity.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bottlers::{Bottle, Keychain, Opener, PrivateKey};
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::rng::OsRng;

fn b64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

const SIGNED_EMPTY_HEADER: &str = "haBYGU1lc3NhZ2Ugd2l0aCBlbXB0eSBoZWFkZXIA9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIQDoHGQacPXpYkm05HM8sz0j0R+kxcahn8CrcneHb1kBXQIgHLaK9FhXVId9yPmvl1NF0K7yoOg9ypGvwJatsGHu0w8=";
const HEADER_WITH_VARIOUS_TYPES: &str =
    "haViY3RkanNvbmNpbnQYKmRib29s9WRudWxs9mZzdHJpbmdqaGVsbG8gdGVzdExUZXN0IG1lc3NhZ2UA9vY=";

/// CBOR -> Bottle -> JSON -> Bottle -> CBOR must preserve all fields.
fn assert_cbor_json_cbor(name: &str, cbor_b64: &str) {
    let cbor = b64(cbor_b64);
    let b = Bottle::from_cbor(&cbor).unwrap();
    let json = b.to_json().unwrap();
    let b2 = Bottle::from_json(&json).unwrap();
    let recbor = b2.to_cbor().unwrap();
    assert_eq!(recbor, cbor, "{name}: CBOR<->JSON not lossless");
}

#[test]
fn cbor_json_roundtrip_preserves_fields() {
    assert_cbor_json_cbor("signedEmptyHeader", SIGNED_EMPTY_HEADER);
    assert_cbor_json_cbor("headerWithVariousTypes", HEADER_WITH_VARIOUS_TYPES);
}

#[test]
fn json_uses_base64url_without_padding() {
    let b = Bottle::new(b"Hello World".to_vec());
    let json = String::from_utf8(b.to_json().unwrap()).unwrap();
    // "Hello World" -> base64url no-pad
    assert!(json.contains("\"msg\":\"SGVsbG8gV29ybGQ\""), "got: {json}");
    assert!(json.contains("\"fmt\":0"));
    assert!(!json.contains("\"hdr\""), "empty header omitted");
    assert!(!json.contains('='), "no base64 padding in JSON");
}

#[test]
fn json_encrypt_sign_open_roundtrip() {
    let recipient = PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng));
    let signer = PrivateKey::Ed25519(Ed25519PrivateKey::generate(&mut OsRng));

    let mut b = Bottle::new(b"json secret".to_vec());
    b.sign(&signer).unwrap();
    b.encrypt(&[recipient.public()]).unwrap();

    let json = b.to_json().unwrap();

    let kc = Keychain::from_keys([recipient]).unwrap();
    let (msg, info) = Opener::new(kc).open_json(&json).expect("open json");
    assert_eq!(msg, b"json secret");
    assert!(info.signed_by_pkix(&signer.public_pkix().unwrap()));
    assert_eq!(info.decryption, 1);
}
