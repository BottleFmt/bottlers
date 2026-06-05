//! Cross-implementation interop: decrypt and verify bottles produced by
//! gobottle, using the same pregenerated keys as gobottle's `aliceandbob_test.go`.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bottlers::{Bottle, Keychain, Opener, PrivateKey};
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;

fn b64(s: &str) -> Vec<u8> {
    STANDARD.decode(s).expect("base64")
}
fn b64url(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

/// Parses an SEC1 EC private key (P-256) by extracting the 32-byte scalar.
fn ec_p256(sec1_b64url: &str) -> PrivateKey {
    let der = b64url(sec1_b64url);
    // SEQUENCE { INTEGER 1, OCTET STRING(32) scalar, ... }
    // 30 77 02 01 01 04 20 <32 bytes>
    assert_eq!(&der[..7], &[0x30, 0x77, 0x02, 0x01, 0x01, 0x04, 0x20]);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&der[7..39]);
    PrivateKey::Ecdsa(EcdsaPrivateKey::from_bytes(&scalar).expect("valid scalar"))
}

/// Parses a PKCS#8 Ed25519 private key by extracting the 32-byte seed.
fn ed25519(pkcs8_b64url: &str) -> PrivateKey {
    let der = b64url(pkcs8_b64url);
    // ... 04 22 04 20 <32-byte seed>
    let seed_start = der.len() - 32;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&der[seed_start..]);
    PrivateKey::Ed25519(Ed25519PrivateKey::from_bytes(seed))
}

const ALICE: &str = "MHcCAQEEIIaSb1TJIeVordec4nMPaRBMsoroc462mpeWDuMEhY1-oAoGCCqGSM49AwEHoUQDQgAE09oIghTDnluvtv0-NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE-KYA";
const BOB: &str = "MHcCAQEEIIPJmeofQddlqI3MNJEBcjEVhNjoR-aYpJXLa3X2q40koAoGCCqGSM49AwEHoUQDQgAEigRCfu95oGP9FNSLWoxhhCDEmgxYG8tMwlFItzAuV6W_fw0Og2BNG3yc0qOb-cEJjQKWRI9i_m1FUc97ajaTrg";
const CHLOE: &str = "MC4CAQAwBQYDK2VwBCIEIPFWBuWK8Ms8fdCdVogl7elV1H56AxiUHMsGl85l4NTB";
const DANIEL: &str = "MC4CAQAwBQYDK2VwBCIEIMyPtgaGrXQ7VwAaZ-7cnwWQaAUpD4mQNzVo0-42CZ5V";

// Vectors (gobottle pregen_test.go)
const ALICE_SIGNED_CLEARTEXT: &str = "haBRSGVsbG8gZnJvbSBBbGljZSEA9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIQCPEWPr/SDCeJXS73kn0oQwXWH70EfgSPtlhyLhvRHHYQIgbvITapFSnsuY2dAQorY+mTLOsMYOJB95nucHxIOzUME=";
const CHLOE_SIGNED_CLEARTEXT: &str = "haBRSGVsbG8gZnJvbSBDaGxvZSEA9oGDAFgsMCowBQYDK2VwAyEATL6PjuPHSTIG2UXmJfEMvJESSp7zLqTncBBc4ElE/D5YQPMG5xy/onBTIEHWfvlayb3lCTfGSClApscby4WP919SOs7c5iq7xsLrYkcGpwGCFKObAbT1C0+omag8EiDWNwY=";
const ALICE_TO_BOB_ENCRYPTED: &str = "haBZAUSFoFhDm5+MnDHvHavDG26WIRahkvXRyopa5BCzFgv25By0k3ase9e/d7hvr+Eq7wKobH/11VQkZmc6gel8TtIAuutYZ7ZmqgKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEu2rfO4Mdj5HJ+ahL7WVbBZXrSzD2FoOOAjqFQ7PDTSfIucQV0gWOjLjPLg7SQ5yiO3pv1RKzJLotq6UyKA3B6iMtBkT4Sn0fVU2Nw0fw0bBjZFj1MPCFnXGqK9Qd3/EyzTA5XzksY+EZaBkOej1ckTc1fpXTEn8HZuPa/PYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIGgCMEL82ywkMC0PuAf4HUqS1wmnzXTtzUHSBy5Aok4ZAiEAn7pHkUVyWhCfb/aiGvwm0PW347iaKDOmywOwrZG1YNk=";
const CHLOE_TO_DANIEL_ENCRYPTED: &str = "haBY6YWgWEbOz5dzuHVoDJGbbegel6QHqyxa7U7NuVznwNxeCQvqTgz8gEPb38MMsTxq5IR+Qu9cfgZ2a2/2DQg+0oJJPRl7ZUYrekXAAoGDAFgsMCowBQYDK2VwAyEA9lV/yry+XMvMGqwhUQXef+3FOjAGD4Mj/gxoJN3X+79YagAsMCowBQYDK2VuAyEAA943R8RqHeZffQ+TH4RlmrtXvklkBdKgddPyttXfvCxrZFHDb9X2oVfQRCbb4fIjc0VqVZT5HvVKf9bz+ymcWbkv+iWCc/Q+B8oLHebH9sE+0zytOy/e1Kamcir2AfaBgwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WECeTEDNYixOSd2tj7BchCLVoLCkmr84L9CwxLo10mYgQoW5wZFOUEME0VdL3kaJfeHuX2/UiRWMk3rssnp6lJgO";

#[test]
fn open_alice_signed_cleartext() {
    let opener = Opener::empty();
    let (msg, info) = opener
        .open_cbor(&b64(ALICE_SIGNED_CLEARTEXT))
        .expect("open");
    assert_eq!(msg, b"Hello from Alice!");
    assert_eq!(info.signatures.len(), 1, "alice ECDSA signature verified");
    assert_eq!(info.decryption, 0);
}

#[test]
fn open_chloe_signed_cleartext() {
    let opener = Opener::empty();
    let (msg, info) = opener
        .open_cbor(&b64(CHLOE_SIGNED_CLEARTEXT))
        .expect("open");
    assert_eq!(msg, b"Hello from Chloe!");
    assert_eq!(info.signatures.len(), 1, "chloe Ed25519 signature verified");
}

#[test]
fn decrypt_alice_to_bob() {
    let kc = Keychain::from_keys([ec_p256(BOB)]).unwrap();
    let opener = Opener::new(kc);
    let (msg, info) = opener
        .open_cbor(&b64(ALICE_TO_BOB_ENCRYPTED))
        .expect("open");
    assert_eq!(msg, b"Secret message from Alice to Bob");
    assert_eq!(info.decryption, 1, "one ECDH decryption performed");
    assert_eq!(
        info.signatures.len(),
        1,
        "alice signed the encrypted bottle"
    );
}

#[test]
fn decrypt_chloe_to_daniel() {
    let kc = Keychain::from_keys([ed25519(DANIEL)]).unwrap();
    let opener = Opener::new(kc);
    let (msg, info) = opener
        .open_cbor(&b64(CHLOE_TO_DANIEL_ENCRYPTED))
        .expect("open");
    assert_eq!(msg, b"Secret message from Chloe to Daniel");
    assert_eq!(info.decryption, 1, "ed25519->x25519 decryption performed");
}

#[test]
fn unused_keys_compile() {
    // alice/chloe parse without panicking (smoke).
    let _ = ec_p256(ALICE);
    let _ = ed25519(CHLOE);
    let _ = Bottle::new(b"x".to_vec());
}
