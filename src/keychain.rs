//! A store of private keys, indexed by their PKIX public-key encoding.

use std::collections::HashMap;

use crate::error::Result;
use crate::key::PrivateKey;

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
        let can_sign = !matches!(key, PrivateKey::X25519(_));
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
}
