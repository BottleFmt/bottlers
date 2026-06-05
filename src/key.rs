//! Key abstraction over the purecrypto primitives.
//!
//! purecrypto exposes per-algorithm key types and an [`AnyPublicKey`] SPKI
//! codec, but no unified private-key type. bottlers defines its own
//! [`PublicKey`] / [`PrivateKey`] enums mirroring gobottle's interface-based
//! dispatch (sign / decrypt / ECDH).

use purecrypto::ec::ecdsa::{EcdsaPrivateKey, EcdsaPublicKey};
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::ec::{BoxedEcdsaPublicKey, CurveId, Ed25519PrivateKey, Ed25519PublicKey};
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};

use crate::error::{BottleError, Result};

/// A public key understood by bottlers.
#[derive(Clone)]
pub enum PublicKey {
    /// An RSA public key.
    Rsa(BoxedRsaPublicKey),
    /// An ECDSA public key (NIST curve); the ECDH encryption path requires P-256.
    Ecdsa(BoxedEcdsaPublicKey),
    /// An Ed25519 public key (signing, or encryption via X25519 conversion).
    Ed25519(Ed25519PublicKey),
    /// A raw X25519 public key (the 32-byte Montgomery u-coordinate).
    X25519([u8; 32]),
}

/// A private key understood by bottlers.
pub enum PrivateKey {
    /// An RSA private key.
    Rsa(BoxedRsaPrivateKey),
    /// A P-256 ECDSA private key (signing and ECDH decryption).
    Ecdsa(EcdsaPrivateKey),
    /// An Ed25519 private key (signing and decryption via X25519 conversion).
    Ed25519(Ed25519PrivateKey),
    /// An X25519 private key (decryption only).
    X25519(X25519PrivateKey),
}

impl PublicKey {
    /// Returns the P-256 ECDSA public key, converting from the boxed form.
    /// Errors if the key is not on P-256.
    pub(crate) fn as_p256(&self) -> Result<EcdsaPublicKey> {
        match self {
            PublicKey::Ecdsa(k) if k.curve() == CurveId::P256 => {
                EcdsaPublicKey::from_sec1(&k.to_sec1())
                    .map_err(|e| BottleError::Crypto(format!("invalid P-256 key: {e:?}")))
            }
            PublicKey::Ecdsa(_) => Err(BottleError::UnsupportedKey("non-P256 ECDSA curve")),
            _ => Err(BottleError::UnsupportedKey("not an ECDSA key")),
        }
    }
}

impl PrivateKey {
    /// Returns the matching public key.
    pub fn public(&self) -> PublicKey {
        match self {
            PrivateKey::Rsa(k) => PublicKey::Rsa(k.public_key()),
            PrivateKey::Ecdsa(k) => {
                let p = k.public_key();
                // Re-box through SEC1 so it shares the parsed representation.
                let boxed = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, &p.to_sec1())
                    .expect("valid P-256 public key");
                PublicKey::Ecdsa(boxed)
            }
            PrivateKey::Ed25519(k) => PublicKey::Ed25519(k.public_key()),
            PrivateKey::X25519(k) => PublicKey::X25519(k.public_key()),
        }
    }

    /// Returns the PKIX/DER SubjectPublicKeyInfo of the matching public key.
    pub fn public_pkix(&self) -> Result<Vec<u8>> {
        crate::pkix::marshal_public_key(&self.public())
    }
}
