//! Key abstraction over the purecrypto primitives.
//!
//! purecrypto exposes per-algorithm key types and an [`AnyPublicKey`] SPKI
//! codec, but no unified private-key type. bottlers defines its own
//! [`PublicKey`] / [`PrivateKey`] enums mirroring gobottle's interface-based
//! dispatch (sign / decrypt / ECDH).

use purecrypto::ec::ecdsa::{EcdsaPrivateKey, EcdsaPublicKey};
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::ec::{BoxedEcdsaPublicKey, CurveId, Ed25519PrivateKey, Ed25519PublicKey};
use purecrypto::mldsa::{
    MlDsa44PrivateKey, MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey,
    MlDsa87PublicKey,
};
use purecrypto::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};
use purecrypto::slhdsa;

use crate::error::{BottleError, Result};
use crate::mlkem::{MlKemPrivate, MlKemPublic};

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
    /// An ML-KEM public key (pure or X25519-hybrid), for encryption.
    MlKem(MlKemPublic),
    /// An ML-DSA-44 public key.
    MlDsa44(MlDsa44PublicKey),
    /// An ML-DSA-65 public key.
    MlDsa65(MlDsa65PublicKey),
    /// An ML-DSA-87 public key.
    MlDsa87(MlDsa87PublicKey),
    /// An SLH-DSA public key.
    SlhDsa(slhdsa::PublicKey),
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
    /// An ML-KEM private key (decryption only).
    MlKem(MlKemPrivate),
    /// An ML-DSA-44 private key.
    MlDsa44(MlDsa44PrivateKey),
    /// An ML-DSA-65 private key.
    MlDsa65(MlDsa65PrivateKey),
    /// An ML-DSA-87 private key.
    MlDsa87(MlDsa87PrivateKey),
    /// An SLH-DSA private key.
    SlhDsa(slhdsa::PrivateKey),
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
            PrivateKey::MlKem(k) => PublicKey::MlKem(k.public()),
            PrivateKey::MlDsa44(k) => PublicKey::MlDsa44(k.public_key()),
            PrivateKey::MlDsa65(k) => PublicKey::MlDsa65(k.public_key()),
            PrivateKey::MlDsa87(k) => PublicKey::MlDsa87(k.public_key()),
            PrivateKey::SlhDsa(k) => PublicKey::SlhDsa(k.public_key()),
        }
    }

    /// Returns true if this key can produce bottle signatures.
    pub(crate) fn can_sign(&self) -> bool {
        !matches!(self, PrivateKey::X25519(_) | PrivateKey::MlKem(_))
    }

    /// Returns the PKIX/DER SubjectPublicKeyInfo of the matching public key.
    pub fn public_pkix(&self) -> Result<Vec<u8>> {
        crate::pkix::marshal_public_key(&self.public())
    }
}
