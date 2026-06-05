//! AES-256-GCM helpers matching Go's `cipher.GCM` semantics, where the 16-byte
//! authentication tag is appended to the ciphertext (`Seal`/`Open`).

use crate::error::{BottleError, Result};
use purecrypto::cipher::{Aes256, Gcm};

/// The GCM nonce size used throughout the Bottle protocol (12 bytes), matching
/// Go's `gcm.NonceSize()`.
pub const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;

/// Seals `plaintext` with AES-256-GCM and an empty AAD, returning
/// `ciphertext || tag` (Go `gcm.Seal(nil, nonce, plaintext, nil)`).
pub fn seal(key: &[u8; 32], nonce: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let gcm = Gcm::new(Aes256::new(key));
    let mut buf = plaintext.to_vec();
    let tag = gcm.encrypt(nonce, &[], &mut buf);
    buf.extend_from_slice(&tag);
    buf
}

/// Opens `ciphertext || tag` produced by [`seal`], verifying the tag.
pub fn open(key: &[u8; 32], nonce: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < TAG_SIZE {
        return Err(BottleError::Malformed("ciphertext shorter than tag".into()));
    }
    let (ct, tag) = data.split_at(data.len() - TAG_SIZE);
    let mut buf = ct.to_vec();
    let mut tag_arr = [0u8; TAG_SIZE];
    tag_arr.copy_from_slice(tag);
    let gcm = Gcm::new(Aes256::new(key));
    gcm.decrypt(nonce, &[], &mut buf, &tag_arr)
        .map_err(|_| BottleError::Crypto("AES-GCM tag mismatch".into()))?;
    Ok(buf)
}
