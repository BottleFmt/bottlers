//! Signature generation and verification, dispatched by key type.
//!
//! Like gobottle's `Sign`/`Verify`, these take the full message buffer and apply
//! the per-algorithm hashing themselves:
//! - RSA: PKCS#1 v1.5 over SHA-256
//! - ECDSA (P-256): ASN.1 DER signature over SHA-256
//! - Ed25519: pure (no pre-hash)

use purecrypto::hash::Sha256;
use purecrypto::x509::{AnyPublicKey, oid};

use crate::error::{BottleError, Result};
use crate::key::{PrivateKey, PublicKey};

/// Signs `msg` with `key`, returning the bottle signature bytes.
pub fn sign(key: &PrivateKey, msg: &[u8]) -> Result<Vec<u8>> {
    if let Some(res) = crate::pqsig::sign(key, msg) {
        return res;
    }
    match key {
        PrivateKey::Rsa(k) => k
            .sign_pkcs1v15::<Sha256>(msg)
            .map_err(|e| BottleError::Crypto(format!("RSA sign: {e:?}"))),
        PrivateKey::Ecdsa(k) => {
            let sig = k
                .sign::<Sha256>(msg)
                .map_err(|e| BottleError::Crypto(format!("ECDSA sign: {e:?}")))?;
            Ok(sig.to_der())
        }
        PrivateKey::Ed25519(k) => Ok(k.sign(msg).to_bytes().to_vec()),
        // X25519 cannot sign; ML-DSA / SLH-DSA were handled above.
        _ => Err(BottleError::UnsupportedKey("key cannot sign")),
    }
}

/// Verifies `sig` over `msg` against the public key, returning
/// [`BottleError::VerifyFailed`] on mismatch.
pub fn verify(pubkey: &PublicKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    if let Some(res) = crate::pqsig::verify(pubkey, msg, sig) {
        return res;
    }
    let result = match pubkey {
        PublicKey::Rsa(k) => AnyPublicKey::Rsa(k.clone()).verify(oid::SHA256_WITH_RSA, msg, sig),
        PublicKey::Ecdsa(k) => {
            AnyPublicKey::Ecdsa(k.clone()).verify(oid::ECDSA_WITH_SHA256, msg, sig)
        }
        PublicKey::Ed25519(k) => AnyPublicKey::Ed25519(k.clone()).verify(oid::ID_ED25519, msg, sig),
        _ => return Err(BottleError::UnsupportedKey("key cannot verify")),
    };
    result.map_err(|_| BottleError::VerifyFailed)
}

/// Verifies a signature given the signer's PKIX public key (as stored in a
/// [`crate::bottle::MessageSignature`]).
pub fn verify_pkix(signer_pkix: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    let pk = crate::pkix::parse_public_key(signer_pkix)?;
    verify(&pk, msg, sig)
}
