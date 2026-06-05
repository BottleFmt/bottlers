//! IDCard interop: open gobottle-produced signed IDCards, re-encode the inner
//! IDCard CBOR byte-exact, and verify the self-signature.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bottlers::{Bottle, IDCard, Opener, PrivateKey};
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::rng::OsRng;

fn b64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("base64")
}

// gobottle interop_test.go IDCard vectors
const IDCARD_MINIMAL: &str = "haBY6oWhYmN0ZmlkY2FyZFjZpgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimACGmlXJSIDgaMBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgAhppVyUiBIFkc2lnbgT2BfYG9gD29gH2gYMAWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgWEcwRQIgB6sLmXxs4iGoIkq6fODzQLJenILaZyBUR5wJ3XxxO4cCIQCmEf6dEZkicJUeByxbkBGOv8wHhDNBdKXre+F7FpLTDw==";
const IDCARD_EMPTY_META: &str = "haBY6oWhYmN0ZmlkY2FyZFjZpgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimACGmlXJSIDgaMBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgAhppVyUiBIFkc2lnbgT2BfYGoAD29gH2gYMAWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgWEgwRgIhALOLrMD7kf3zIcSUVN3WdVoocLcOHp0WdPzRjEjdZ1YUAiEA1KsD/PqAF50w15H6H/6Bp+vG/vIfRC1cC9uCOEbdxVs=";
const IDCARD_MULTIPLE_KEYS: &str = "haBZAWWFoWJjdGZpZGNhcmRZAVOmAVhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYAIaaVclIgOCowFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimACGmlXJSIEgWRzaWduowFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k64CGmlXJSIEgWdkZWNyeXB0BPYF9gahZG5hbWVlQWxpY2UA9vYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhGMEQCIG61XNinbnrTCVaC+O8WYe2z7D6gJIpYKGsUDmKjarZuAiAWqY6egk/elce5bkhiotumipTD4SjchsqXQK/OOPu+sQ==";
const IDCARD_WITH_EXPIRY: &str = "haBY+4WhYmN0ZmlkY2FyZFjqpgFYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimACGmlXJSIDgaQBWFswWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATT2giCFMOeW6+2/T40oyFNLad8LdPNHgNadkrtzPMU9lIfpsk3mgxkKnlful8jgFsjJNW0Z5EqDoZOnPN8T4pgAhppVyUiAxprOFiiBIFkc2lnbgT2BfYGoWRuYW1lZUFsaWNlAPb2AfaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYRzBFAiEAjSHUHctRCSoNVVPwpiRLnVrhjeq9QTwjMPEOUGcGlv4CIEGqg089iHG7hMgs3RZ9LArebE91afQydJCHmvbXBBQQ";

fn assert_idcard_vector(name: &str, b64s: &str) -> IDCard {
    let raw = b64(b64s);
    // Open the signed bottle (verifies the self-signature path runs).
    let (payload, info) = Opener::empty().open_cbor(&raw).expect("open idcard bottle");
    assert!(!info.signatures.is_empty(), "{name}: signed");

    // Parse and re-encode the inner IDCard CBOR byte-exact.
    let card = IDCard::from_cbor(&payload).unwrap_or_else(|e| panic!("{name}: parse: {e}"));
    let re = card.to_cbor().unwrap();
    assert_eq!(re, payload, "{name}: IDCard CBOR not byte-exact");

    // from_signed enforces the self-signature.
    IDCard::from_signed(&raw).unwrap_or_else(|e| panic!("{name}: from_signed: {e}"));
    card
}

#[test]
fn idcard_vectors_roundtrip_and_verify() {
    let minimal = assert_idcard_vector("idcardMinimal", IDCARD_MINIMAL);
    assert_eq!(minimal.subkeys.len(), 1);
    assert!(minimal.subkeys[0].has_purpose("sign"));
    assert!(minimal.meta.is_none(), "minimal Meta is null");
    assert!(minimal.revoke.is_none() && minimal.groups.is_none());

    let empty_meta = assert_idcard_vector("idcardEmptyMeta", IDCARD_EMPTY_META);
    assert!(
        empty_meta.meta.as_ref().is_some_and(|m| m.is_empty()),
        "empty Meta is an empty map, not null"
    );

    let multi = assert_idcard_vector("idcardMultipleKeys", IDCARD_MULTIPLE_KEYS);
    assert_eq!(multi.subkeys.len(), 2);
    assert_eq!(
        multi
            .meta
            .as_ref()
            .and_then(|m| m.get("name"))
            .map(String::as_str),
        Some("Alice")
    );

    let expiry = assert_idcard_vector("idcardWithExpiry", IDCARD_WITH_EXPIRY);
    assert!(
        expiry.subkeys.iter().any(|s| s.expires.is_some()),
        "one subkey has an expiry"
    );
}

#[test]
fn idcard_sign_and_verify_roundtrip() {
    let key = PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng));
    let mut card = IDCard::new(&key).unwrap();
    card.set_key_purposes(card.self_key.clone(), &["sign", "decrypt"]);

    let signed = card.sign(&key).unwrap();
    let parsed = IDCard::from_signed(&signed).expect("verify own signature");
    assert_eq!(parsed.self_key, card.self_key);
    assert!(parsed.subkeys[0].has_purpose("decrypt"));

    // A bottle that isn't signed by the owner is rejected.
    let other = PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng));
    let bad = card.sign(&other).unwrap();
    assert!(IDCard::from_signed(&bad).is_err());

    // Sanity: the signed blob is a valid bottle.
    assert!(Bottle::from_cbor(&signed).is_ok());
}

#[test]
fn membership_sign_and_verify() {
    use bottlers::Membership;

    let group = PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng));
    let subject = PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng));
    let group_pkix = group.public_pkix().unwrap();
    let subject_pkix = subject.public_pkix().unwrap();

    let mut m = Membership::new(subject_pkix.clone(), group_pkix.clone(), 1_700_000_000);
    m.info
        .as_mut()
        .unwrap()
        .insert("name".into(), "Carol".into());
    m.sign(&group).unwrap();

    // Self-signed verification (sign key == group key).
    m.verify(None).expect("membership verifies");

    // It survives being embedded in an IDCard's groups and re-decoded.
    let card = bottlers::IDCard {
        self_key: group_pkix.clone(),
        issued: 0,
        subkeys: vec![],
        revoke: None,
        groups: Some(vec![m.clone()]),
        meta: None,
    };
    let reparsed = bottlers::IDCard::from_cbor(&card.to_cbor().unwrap()).unwrap();
    reparsed.groups.unwrap()[0]
        .verify(None)
        .expect("re-decoded membership verifies");

    // Tampering breaks verification.
    let mut tampered = m.clone();
    tampered.status = "suspended".into();
    assert!(tampered.verify(None).is_err());
}
