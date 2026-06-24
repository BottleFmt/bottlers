//! Keychain serialization round trips: plaintext and password-encrypted, over
//! a mix of classical and post-quantum key types (including the X25519-hybrid
//! ML-KEM form, which has no standard PKCS#8 encoding).

use std::collections::BTreeSet;

use bottlers::mlkem::{MlKemPrivate, MlKemVariant};
use bottlers::{Bottle, Keychain, Opener, PrivateKey};
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::mldsa::MlDsa44PrivateKey;
use purecrypto::rng::OsRng;
use purecrypto::slhdsa::{self, ParamSet};

/// A keychain spanning every entry kind: PKCS#8 (RSA-less, to stay fast),
/// the bare P-256 ECDSA scalar, and ML-KEM (pure + hybrid).
fn sample_keys() -> Vec<PrivateKey> {
    vec![
        PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng)),
        PrivateKey::Ed25519(Ed25519PrivateKey::generate(&mut OsRng)),
        PrivateKey::X25519(X25519PrivateKey::generate(&mut OsRng)),
        PrivateKey::MlDsa44(MlDsa44PrivateKey::generate(&mut OsRng).0),
        PrivateKey::SlhDsa(slhdsa::PrivateKey::generate(ParamSet::Sha2_128f, &mut OsRng).0),
        PrivateKey::MlKem(MlKemPrivate::generate(MlKemVariant::V768, false)),
        PrivateKey::MlKem(MlKemPrivate::generate(MlKemVariant::V1024, true)),
    ]
}

/// The set of PKIX public keys held by a keychain, used to compare two
/// keychains independently of (unstable) storage order.
fn pkix_set(kc: &Keychain) -> BTreeSet<Vec<u8>> {
    kc.keys().map(|k| k.public_pkix().unwrap()).collect()
}

#[test]
fn roundtrip_plaintext() {
    let kc = Keychain::from_keys(sample_keys()).unwrap();
    let want = pkix_set(&kc);

    let blob = kc.serialize(None).unwrap();
    let restored = Keychain::deserialize(&blob, None).unwrap();

    assert_eq!(pkix_set(&restored), want);
}

#[test]
fn roundtrip_encrypted() {
    let kc = Keychain::from_keys(sample_keys()).unwrap();
    let want = pkix_set(&kc);
    let password = b"correct horse battery staple";

    let blob = kc.serialize(Some(password)).unwrap();
    // The encrypted form must not equal the plaintext form.
    assert_ne!(blob, kc.serialize(None).unwrap());

    let restored = Keychain::deserialize(&blob, Some(password)).unwrap();
    assert_eq!(pkix_set(&restored), want);

    // Wrong password, and password/plaintext mismatches, must fail rather than
    // silently return a bogus keychain.
    assert!(Keychain::deserialize(&blob, Some(b"wrong")).is_err());
    assert!(Keychain::deserialize(&blob, None).is_err());
}

#[test]
fn deserialized_hybrid_mlkem_key_still_decrypts() {
    // Prove the secret material survives the round trip, not just the public
    // half: seal to a hybrid ML-KEM recipient, restore the keychain from an
    // encrypted blob, then open the bottle with the restored key.
    let recipient = PrivateKey::MlKem(MlKemPrivate::generate(MlKemVariant::V768, true));
    let mut bottle = Bottle::new(b"hybrid secret".to_vec());
    bottle.encrypt(&[recipient.public()]).unwrap();

    let kc = Keychain::from_keys([recipient]).unwrap();
    let blob = kc.serialize(Some(b"pw")).unwrap();
    let restored = Keychain::deserialize(&blob, Some(b"pw")).unwrap();

    let (msg, _info) = Opener::new(restored).open(bottle).expect("open");
    assert_eq!(msg, b"hybrid secret");
}
