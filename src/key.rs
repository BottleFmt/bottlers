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
use purecrypto::x509::{AnyPrivateKey, Pkcs8ReadOptions};

use crate::error::{BottleError, Result};
use crate::mlkem::{MlKemPrivate, MlKemPublic};

/// A public key understood by bottlers.
#[derive(Clone)]
#[allow(clippy::large_enum_variant)]
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
#[allow(clippy::large_enum_variant)]
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

    /// Serializes this key for keychain storage, returning an entry-kind
    /// discriminator and its payload.
    ///
    /// Kind [`ENTRY_PKCS8`] is a standard PKCS#8 `PrivateKeyInfo` (decoded on
    /// the way back via purecrypto's unified [`AnyPrivateKey`]). Kind
    /// [`ENTRY_ECDSA_P256`] is a bare P-256 scalar — bottlers keeps ECDSA in
    /// its concrete P-256 form, which `AnyPrivateKey` cannot hand back. Kind
    /// [`ENTRY_MLKEM`] is bottlers' own ML-KEM framing: the X25519-hybrid form
    /// has no standard PKCS#8 OID, so it cannot ride the unified path either.
    pub(crate) fn to_entry(&self) -> Result<(u8, Vec<u8>)> {
        Ok(match self {
            PrivateKey::Rsa(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::Ecdsa(k) => (ENTRY_ECDSA_P256, k.to_bytes().to_vec()),
            PrivateKey::Ed25519(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::X25519(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::MlDsa44(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::MlDsa65(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::MlDsa87(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::SlhDsa(k) => (ENTRY_PKCS8, k.to_pkcs8_der()),
            PrivateKey::MlKem(k) => (ENTRY_MLKEM, k.to_key_bytes()),
        })
    }

    /// Reconstructs a key from an entry produced by [`to_entry`](Self::to_entry).
    pub(crate) fn from_entry(kind: u8, data: &[u8]) -> Result<Self> {
        match kind {
            ENTRY_PKCS8 => {
                let any = AnyPrivateKey::from_pkcs8_der(data, Pkcs8ReadOptions::new())
                    .map_err(|e| BottleError::Pkix(format!("{e:?}")))?;
                PrivateKey::from_any(any)
            }
            ENTRY_ECDSA_P256 => {
                let arr: [u8; 32] = data
                    .try_into()
                    .map_err(|_| BottleError::Malformed("bad P-256 scalar length".into()))?;
                Ok(PrivateKey::Ecdsa(
                    EcdsaPrivateKey::from_bytes(&arr)
                        .map_err(|e| BottleError::Crypto(format!("{e:?}")))?,
                ))
            }
            ENTRY_MLKEM => Ok(PrivateKey::MlKem(MlKemPrivate::from_key_bytes(data)?)),
            _ => Err(BottleError::Malformed(format!(
                "unknown keychain entry kind {kind}"
            ))),
        }
    }

    /// Maps a unified [`AnyPrivateKey`] onto the subset of key types bottlers
    /// supports. (ECDSA never arrives here — it uses [`ENTRY_ECDSA_P256`].)
    fn from_any(any: AnyPrivateKey) -> Result<Self> {
        Ok(match any {
            AnyPrivateKey::Rsa(k) => PrivateKey::Rsa(k),
            AnyPrivateKey::Ed25519(k) => PrivateKey::Ed25519(k),
            AnyPrivateKey::X25519(k) => PrivateKey::X25519(k),
            AnyPrivateKey::MlDsa44(k) => PrivateKey::MlDsa44(k),
            AnyPrivateKey::MlDsa65(k) => PrivateKey::MlDsa65(k),
            AnyPrivateKey::MlDsa87(k) => PrivateKey::MlDsa87(k),
            AnyPrivateKey::SlhDsa(k) => PrivateKey::SlhDsa(k),
            _ => return Err(BottleError::UnsupportedKey("key type unsupported by bottlers")),
        })
    }
}

/// Keychain entry kind: a standard PKCS#8 `PrivateKeyInfo`.
pub(crate) const ENTRY_PKCS8: u8 = 0;
/// Keychain entry kind: bottlers' ML-KEM framing (pure or X25519-hybrid).
pub(crate) const ENTRY_MLKEM: u8 = 1;
/// Keychain entry kind: a bare 32-byte P-256 ECDSA scalar.
pub(crate) const ENTRY_ECDSA_P256: u8 = 2;
