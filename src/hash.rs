//! Hashing helpers built on purecrypto's `Digest` implementations.

use purecrypto::hash::{Digest, Sha256, Sha512};

/// Computes a single SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data)
}

/// Computes a single SHA-512 digest.
pub fn sha512(data: &[u8]) -> [u8; 64] {
    Sha512::digest(data)
}
