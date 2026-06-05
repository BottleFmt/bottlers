//! Opening (decrypting + verifying) bottles.

use crate::aead::{self, NONCE_SIZE};
use crate::bottle::{Bottle, MessageFormat, MessageSignature};
use crate::error::{BottleError, Result};
use crate::keychain::Keychain;
use crate::short;
use crate::{pkix, sign};

/// Opens bottles using a set of keys.
#[derive(Default)]
pub struct Opener {
    keychain: Keychain,
}

/// The result of opening a bottle: the verified signatures and the chain of
/// bottle layers traversed (outermost first).
pub struct OpenResult {
    /// Number of decryptions performed.
    pub decryption: usize,
    /// Signatures that were successfully verified.
    pub signatures: Vec<MessageSignature>,
    /// The chain of bottles, outermost first.
    pub bottles: Vec<Bottle>,
}

impl OpenResult {
    /// Returns the innermost bottle (carrying any final metadata).
    pub fn last(&self) -> &Bottle {
        self.bottles.last().expect("OpenResult has no bottles")
    }

    /// Returns the outermost bottle (the one passed to open).
    pub fn first(&self) -> &Bottle {
        self.bottles.first().expect("OpenResult has no bottles")
    }

    /// Returns true if the message was signed by the given PKIX public key.
    pub fn signed_by_pkix(&self, pkix: &[u8]) -> bool {
        self.signatures.iter().any(|s| s.signer == pkix)
    }
}

impl Opener {
    /// Returns an opener with no keys (can verify signatures and open cleartext,
    /// but cannot decrypt).
    pub fn empty() -> Self {
        Opener::default()
    }

    /// Builds an opener from a keychain.
    pub fn new(keychain: Keychain) -> Self {
        Opener { keychain }
    }

    /// Opens `b`, returning the embedded payload and an [`OpenResult`].
    pub fn open(&self, b: Bottle) -> Result<(Vec<u8>, OpenResult)> {
        let mut res = OpenResult {
            decryption: 0,
            signatures: Vec::new(),
            bottles: Vec::new(),
        };
        let mut current = b;

        loop {
            res.bottles.push(current.clone());
            let bottle = res.bottles.last().unwrap();

            if let Some(sigs) = &bottle.signatures {
                for sig in sigs {
                    sign::verify_pkix(&sig.signer, &bottle.message, &sig.data)?;
                    res.signatures.push(sig.clone());
                }
            }

            match bottle.format {
                MessageFormat::ClearText => {
                    return Ok((bottle.message.clone(), res));
                }
                MessageFormat::CborBottle => {
                    let child = Bottle::from_cbor(&bottle.message)?;
                    current = child;
                }
                MessageFormat::JsonBottle => {
                    let child = crate::json::bottle_from_json(&bottle.message)?;
                    current = child;
                }
                MessageFormat::Aes => {
                    let key = self.recover_content_key(bottle)?;
                    if bottle.message.len() < NONCE_SIZE {
                        return Err(BottleError::Malformed("AES message too short".into()));
                    }
                    let (nonce, ct) = bottle.message.split_at(NONCE_SIZE);
                    let plaintext = aead::open(&key, nonce, ct)?;
                    res.decryption += 1;
                    current = Bottle::from_cbor(&plaintext)?;
                }
            }
        }
    }

    /// Opens a CBOR-encoded bottle.
    pub fn open_cbor(&self, data: &[u8]) -> Result<(Vec<u8>, OpenResult)> {
        self.open(Bottle::from_cbor(data)?)
    }

    /// Opens a JSON-encoded bottle.
    pub fn open_json(&self, data: &[u8]) -> Result<(Vec<u8>, OpenResult)> {
        self.open(Bottle::from_json(data)?)
    }

    /// Tries each recipient slot against the keychain, returning the 32-byte
    /// content key on the first success.
    fn recover_content_key(&self, bottle: &Bottle) -> Result<[u8; 32]> {
        let recipients = bottle
            .recipients
            .as_ref()
            .ok_or(BottleError::NoAppropriateKey)?;
        let mut last_err = BottleError::NoAppropriateKey;
        for r in recipients {
            // The stored recipient key may be a parsed form; match by PKIX bytes.
            if let Some(priv_key) = self.keychain.get_key(&r.recipient) {
                match short::decrypt_short(&r.data, priv_key) {
                    Ok(k) if k.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&k);
                        return Ok(key);
                    }
                    Ok(_) => last_err = BottleError::Crypto("content key not 32 bytes".into()),
                    Err(e) => last_err = e,
                }
            }
        }
        Err(last_err)
    }
}

/// Re-marshals a recipient public key to canonical PKIX, used when matching
/// keychain entries that were parsed from a different but equivalent encoding.
#[allow(dead_code)]
pub(crate) fn canonical_recipient_pkix(pkix: &[u8]) -> Vec<u8> {
    pkix::parse_public_key(pkix)
        .and_then(|k| pkix::marshal_public_key(&k))
        .unwrap_or_else(|_| pkix.to_vec())
}
