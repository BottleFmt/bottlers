//! Write-side round trips: encrypt/sign with bottlers, then open with bottlers,
//! across every supported classical recipient and signer type.

use bottlers::{Bottle, Keychain, Opener, PrivateKey, PublicKey};
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::rng::OsRng;

fn gen_ecdsa() -> PrivateKey {
    PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng))
}
fn gen_ed25519() -> PrivateKey {
    PrivateKey::Ed25519(Ed25519PrivateKey::generate(&mut OsRng))
}
fn gen_x25519() -> PrivateKey {
    PrivateKey::X25519(X25519PrivateKey::generate(&mut OsRng))
}

fn open_with(key: PrivateKey, bottle: &Bottle) -> Vec<u8> {
    let kc = Keychain::from_keys([key]).unwrap();
    let opener = Opener::new(kc);
    opener.open(bottle.clone()).expect("open").0
}

#[test]
fn sign_then_open_ecdsa_and_ed25519() {
    for signer in [gen_ecdsa(), gen_ed25519()] {
        let pkix = signer.public_pkix().unwrap();
        let mut b = Bottle::new(b"signed payload".to_vec());
        b.sign(&signer).unwrap();
        let (msg, info) = Opener::empty().open(b).expect("open");
        assert_eq!(msg, b"signed payload");
        assert!(info.signed_by_pkix(&pkix));
    }
}

#[test]
fn encrypt_to_each_recipient_type() {
    let recipients = [gen_ecdsa(), gen_ed25519(), gen_x25519()];
    for recip in recipients {
        let pubkey: PublicKey = recip.public();
        let mut b = Bottle::new(b"hello recipient".to_vec());
        b.encrypt(&[pubkey]).unwrap();
        // A foreign opener cannot read it.
        assert!(Opener::empty().open(b.clone()).is_err());
        // The intended recipient can.
        let msg = open_with(recip, &b);
        assert_eq!(msg, b"hello recipient");
    }
}

#[test]
fn multi_recipient_encrypt() {
    let alice = gen_ecdsa();
    let bob = gen_ed25519();
    let carol = gen_x25519();
    let mut b = Bottle::new(b"group secret".to_vec());
    b.encrypt(&[alice.public(), bob.public(), carol.public()]).unwrap();

    assert_eq!(open_with(alice, &b), b"group secret");
    assert_eq!(open_with(bob, &b), b"group secret");
    assert_eq!(open_with(carol, &b), b"group secret");
}

#[test]
fn sign_then_encrypt_then_sign() {
    let signer = gen_ecdsa();
    let recipient = gen_ed25519();
    let outer_signer = gen_ed25519();

    let mut b = Bottle::new(b"layered".to_vec());
    b.sign(&signer).unwrap();
    b.encrypt(&[recipient.public()]).unwrap();
    b.sign(&outer_signer).unwrap();

    let kc = Keychain::from_keys([recipient]).unwrap();
    let (msg, info) = Opener::new(kc).open(b).expect("open");
    assert_eq!(msg, b"layered");
    assert!(info.signed_by_pkix(&signer.public_pkix().unwrap()));
    assert!(info.signed_by_pkix(&outer_signer.public_pkix().unwrap()));
    assert_eq!(info.decryption, 1);
}
