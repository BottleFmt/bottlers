//! A store of private keys, indexed by their PKIX public-key encoding.

use std::collections::HashMap;

use ciborium::value::Value;
use purecrypto::kdf::pbes2::{self, Pbes2Params};
use purecrypto::rng::OsRng;

use crate::cbor;
use crate::error::{BottleError, Result};
use crate::key::PrivateKey;

/// On-disk container format version, stored as the first element of the
/// top-level CBOR array.
const FORMAT_VERSION: i64 = 1;

/// Holds private keys usable to sign or decrypt bottles.
#[derive(Default)]
pub struct Keychain {
    keys: HashMap<Vec<u8>, PrivateKey>,
    sign_key: Option<Vec<u8>>,
}

impl Keychain {
    /// Returns a new, empty keychain.
    pub fn new() -> Self {
        Keychain::default()
    }

    /// Adds a private key, indexing it by its PKIX public key. The first
    /// signing-capable key added becomes the default signer.
    pub fn add_key(&mut self, key: PrivateKey) -> Result<()> {
        let pkix = key.public_pkix()?;
        let can_sign = key.can_sign();
        if can_sign && self.sign_key.is_none() {
            self.sign_key = Some(pkix.clone());
        }
        self.keys.insert(pkix, key);
        Ok(())
    }

    /// Builds a keychain from the given keys.
    pub fn from_keys(keys: impl IntoIterator<Item = PrivateKey>) -> Result<Self> {
        let mut kc = Keychain::new();
        for k in keys {
            kc.add_key(k)?;
        }
        Ok(kc)
    }

    /// Returns the private key matching the given PKIX public key, if held.
    pub fn get_key(&self, pkix: &[u8]) -> Option<&PrivateKey> {
        self.keys.get(pkix)
    }

    /// Returns the default signing key, if any.
    pub fn first_signer(&self) -> Option<&PrivateKey> {
        self.sign_key.as_ref().and_then(|k| self.keys.get(k))
    }

    /// Iterates over all stored keys.
    pub fn keys(&self) -> impl Iterator<Item = &PrivateKey> {
        self.keys.values()
    }

    /// Serializes the keychain, including all private keys, to a byte string.
    ///
    /// Each key is stored as standard PKCS#8 (ECDSA as a bare P-256 scalar,
    /// ML-KEM in bottlers' own framing), wrapped in a versioned CBOR container.
    /// When `password` is `Some`, the whole container is encrypted under PBES2
    /// (PBKDF2-HMAC-SHA256 + AES-256-GCM) and the output is a DER
    /// `EncryptedPrivateKeyInfo`; when `None`, the plain CBOR is returned.
    ///
    /// Key ordering is not stable across calls (the backing store is a hash
    /// map); callers needing determinism should sort the output's keys
    /// themselves before comparing.
    pub fn serialize(&self, password: Option<&[u8]>) -> Result<Vec<u8>> {
        let mut entries = Vec::with_capacity(self.keys.len());
        for key in self.keys.values() {
            let (kind, payload) = key.to_entry()?;
            entries.push(Value::Array(vec![
                Value::Integer(kind.into()),
                Value::Bytes(payload),
            ]));
        }
        let container = Value::Array(vec![
            Value::Integer(FORMAT_VERSION.into()),
            Value::Array(entries),
        ]);
        let plain = cbor::to_vec(&container)?;
        match password {
            None => Ok(plain),
            Some(pw) => Ok(pbes2::encrypt(
                &plain,
                pw,
                &Pbes2Params::default(),
                &mut OsRng,
            )),
        }
    }

    /// Reconstructs a keychain from [`serialize`](Self::serialize) output.
    ///
    /// `password` must match what was passed to `serialize`: `Some` to decrypt
    /// a PBES2-wrapped container, `None` for a plain one. A wrong password (or
    /// passing one when the data is not encrypted) surfaces as an error.
    pub fn deserialize(data: &[u8], password: Option<&[u8]>) -> Result<Self> {
        let plain = match password {
            None => data.to_vec(),
            Some(pw) => pbes2::decrypt(data, pw)
                .map_err(|e| BottleError::Crypto(format!("keychain decryption failed: {e:?}")))?,
        };

        let container = cbor::from_slice(&plain)?;
        let top = cbor::as_array(&container)?;
        if top.len() != 2 {
            return Err(BottleError::Malformed("invalid keychain container".into()));
        }
        let version = cbor::as_i64(&top[0])?;
        if version != FORMAT_VERSION {
            return Err(BottleError::Malformed(format!(
                "unsupported keychain version {version}"
            )));
        }

        let mut kc = Keychain::new();
        for entry in cbor::as_array(&top[1])? {
            let parts = cbor::as_array(entry)?;
            if parts.len() != 2 {
                return Err(BottleError::Malformed("invalid keychain entry".into()));
            }
            let kind: u8 = cbor::as_i64(&parts[0])?
                .try_into()
                .map_err(|_| BottleError::Malformed("entry kind out of range".into()))?;
            let payload = cbor::as_bytes(&parts[1])?;
            kc.add_key(PrivateKey::from_entry(kind, &payload)?)?;
        }
        Ok(kc)
    }
}
