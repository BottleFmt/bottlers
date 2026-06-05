//! [`Bottle`] encryption and signing (the write side of the protocol).

use purecrypto::rng::{OsRng, RngCore};

use crate::aead::{self, NONCE_SIZE};
use crate::bottle::{Bottle, MessageFormat, MessageRecipient, MessageSignature};
use crate::error::{BottleError, Result};
use crate::key::{PrivateKey, PublicKey};
use crate::memclr::mem_clr;
use crate::{pkix, short, sign};

impl Bottle {
    /// Encrypts the bottle so only `recipients` can decrypt it. The bottle is
    /// bottled up first unless it is already a clean nested bottle.
    pub fn encrypt(&mut self, recipients: &[PublicKey]) -> Result<()> {
        if !self.is_clean_bottle() {
            self.bottle_up()?;
        }

        let mut content_key = [0u8; 32];
        OsRng.fill_bytes(&mut content_key);

        let mut nonce = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);

        let sealed = aead::seal(&content_key, &nonce, &self.message);

        let mut out_recipients = Vec::new();
        for r in recipients {
            let data = short::encrypt_short(&content_key, r)?;
            let pkix = pkix::marshal_public_key(r)?;
            out_recipients.push(MessageRecipient {
                typ: 0,
                recipient: pkix,
                data,
            });
        }
        mem_clr(&mut content_key);

        if out_recipients.is_empty() {
            return Err(BottleError::EncryptNoRecipient);
        }

        let mut message = Vec::with_capacity(NONCE_SIZE + sealed.len());
        message.extend_from_slice(&nonce);
        message.extend_from_slice(&sealed);

        self.header.clear();
        self.message = message;
        self.format = MessageFormat::Aes;
        self.recipients = Some(out_recipients);
        Ok(())
    }

    /// Signs the bottle with `key`. Can be called multiple times. If the bottle
    /// carries header values, it is bottled up first so the header is signed.
    pub fn sign(&mut self, key: &PrivateKey) -> Result<()> {
        if !self.header.is_empty() {
            self.bottle_up()?;
        }

        let signer = key.public_pkix()?;
        let data = sign::sign(key, &self.message)?;

        let signature = MessageSignature {
            typ: 0,
            signer,
            data,
        };
        self.signatures.get_or_insert_with(Vec::new).push(signature);
        Ok(())
    }
}
