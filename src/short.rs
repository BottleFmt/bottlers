//! Short-buffer encryption: encrypt/decrypt the per-message content key for a
//! single recipient, dispatched by key type (gobottle's
//! `EncryptShortBuffer`/`DecryptShortBuffer`).

use purecrypto::hash::Sha256;
use purecrypto::rng::OsRng;

use crate::ecdh;
use crate::ed_convert;
use crate::error::{BottleError, Result};
use crate::key::{PrivateKey, PublicKey};

/// Encrypts the small buffer `k` (the content key) for `recipient`.
pub fn encrypt_short(k: &[u8], recipient: &PublicKey) -> Result<Vec<u8>> {
    match recipient {
        PublicKey::Rsa(pk) => pk
            .encrypt_oaep::<Sha256, _>(k, &[], &mut OsRng)
            .map_err(|e| BottleError::Crypto(format!("RSA-OAEP: {e:?}"))),
        PublicKey::Ecdsa(_) => ecdh::encrypt_p256(k, &recipient.as_p256()?),
        PublicKey::Ed25519(pk) => {
            let u = ed_convert::ed25519_public_to_x25519(&pk.to_bytes())?;
            ecdh::encrypt_x25519(k, &u)
        }
        PublicKey::X25519(u) => ecdh::encrypt_x25519(k, u),
        PublicKey::MlKem(pk) => crate::mlkem::encrypt(k, pk),
        _ => Err(BottleError::UnsupportedKey("key cannot be an encryption recipient")),
    }
}

/// Decrypts a short buffer with `recipient`'s private key.
pub fn decrypt_short(data: &[u8], recipient: &PrivateKey) -> Result<Vec<u8>> {
    match recipient {
        PrivateKey::Rsa(sk) => sk
            .decrypt_oaep::<Sha256>(data, &[])
            .map_err(|e| BottleError::Crypto(format!("RSA-OAEP: {e:?}"))),
        PrivateKey::MlKem(sk) => crate::mlkem::decrypt(data, sk),
        // ECDSA (P-256), Ed25519, and X25519 all use the ECDH envelope.
        _ => ecdh::decrypt(data, recipient),
    }
}
