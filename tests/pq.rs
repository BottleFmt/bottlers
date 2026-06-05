//! Post-quantum round trips: ML-KEM (pure + hybrid), ML-DSA, SLH-DSA.

use bottlers::mlkem::{MlKemPrivate, MlKemVariant};
use bottlers::{Bottle, Keychain, Opener, PrivateKey};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::slhdsa::{self, ParamSet};

fn open_with(key: PrivateKey, bottle: &Bottle) -> Vec<u8> {
    let kc = Keychain::from_keys([key]).unwrap();
    Opener::new(kc).open(bottle.clone()).expect("open").0
}

#[test]
fn mlkem_pure_and_hybrid_roundtrip() {
    for (variant, hybrid) in [
        (MlKemVariant::V768, false),
        (MlKemVariant::V768, true),
        (MlKemVariant::V1024, false),
        (MlKemVariant::V1024, true),
    ] {
        let recipient = PrivateKey::MlKem(MlKemPrivate::generate(variant, hybrid));
        let mut b = Bottle::new(b"pq secret".to_vec());
        b.encrypt(&[recipient.public()]).unwrap();

        // round-trips through CBOR (exercises PKIX marshal/parse of the key)
        let cbor = b.to_cbor().unwrap();
        let parsed = Bottle::from_cbor(&cbor).unwrap();

        assert!(Opener::empty().open(parsed.clone()).is_err());
        assert_eq!(open_with(recipient, &parsed), b"pq secret");
    }
}

#[test]
fn mldsa_sign_roundtrip() {
    let signers = [
        PrivateKey::MlDsa44(MlDsa44PrivateKey::generate(&mut OsRng).0),
        PrivateKey::MlDsa65(MlDsa65PrivateKey::generate(&mut OsRng).0),
        PrivateKey::MlDsa87(MlDsa87PrivateKey::generate(&mut OsRng).0),
    ];
    for signer in signers {
        let pkix = signer.public_pkix().unwrap();
        let mut b = Bottle::new(b"ml-dsa signed".to_vec());
        b.sign(&signer).unwrap();
        let cbor = b.to_cbor().unwrap();
        let (msg, info) = Opener::empty().open_cbor(&cbor).expect("open");
        assert_eq!(msg, b"ml-dsa signed");
        assert!(info.signed_by_pkix(&pkix));
    }
}

#[test]
fn slhdsa_sign_roundtrip() {
    // Use a fast parameter set to keep the test quick.
    let (sk, _pk) = slhdsa::PrivateKey::generate(ParamSet::Sha2_128f, &mut OsRng);
    let signer = PrivateKey::SlhDsa(sk);
    let pkix = signer.public_pkix().unwrap();

    let mut b = Bottle::new(b"slh-dsa signed".to_vec());
    b.sign(&signer).unwrap();
    let cbor = b.to_cbor().unwrap();
    let (msg, info) = Opener::empty().open_cbor(&cbor).expect("open");
    assert_eq!(msg, b"slh-dsa signed");
    assert!(info.signed_by_pkix(&pkix));
}
