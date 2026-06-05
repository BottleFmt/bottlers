//! Conversions between Ed25519 (Edwards) keys and X25519 (Montgomery) keys,
//! matching gobottle's use of `extra25519`.
//!
//! - Private: `clamp(SHA-512(seed)[..32])` is the X25519 scalar.
//! - Public: `u = (1 + y) / (1 - y) mod p`, where `y` is the lower 255 bits of
//!   the compressed Ed25519 public key and `p = 2^255 − 19`. (The x-sign bit in
//!   the top bit of the last byte is ignored, exactly as in the birational map.)

use purecrypto::bignum::{BoxedMontModulus, BoxedUint, inv_mod_boxed};
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;

use crate::error::{BottleError, Result};
use crate::hash::sha512;

/// `p = 2^255 − 19`, big-endian.
const P_BE: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed,
];

/// Derives the X25519 private key corresponding to an Ed25519 private key.
pub fn ed25519_private_to_x25519(sk: &Ed25519PrivateKey) -> X25519PrivateKey {
    let seed = sk.to_bytes();
    let digest = sha512(&seed);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&digest[..32]);
    // X25519PrivateKey clamps on use, matching gobottle's explicit clamping.
    X25519PrivateKey::from_bytes(scalar)
}

/// Converts an Ed25519 public key (32-byte compressed) to the X25519
/// Montgomery u-coordinate.
pub fn ed25519_public_to_x25519(ed_pub: &[u8; 32]) -> Result<[u8; 32]> {
    // y is the lower 255 bits, little-endian; clear the x-sign bit.
    let mut y_le = *ed_pub;
    y_le[31] &= 0x7f;
    let mut y_be = y_le;
    y_be.reverse();

    let modulus = BoxedUint::from_be_bytes(&P_BE);
    let mont = BoxedMontModulus::new(&modulus);
    let one = BoxedUint::from_be_bytes(&[1]);
    let y = BoxedUint::from_be_bytes(&y_be);

    // num = 1 + y ; den = 1 - y   (all mod p)
    let num = mont.add_mod(&one, &y);
    let den = mont.sub_mod(&one, &y);

    let den_inv = inv_mod_boxed(&den, &modulus)
        .ok_or_else(|| BottleError::Crypto("non-invertible (1 - y) in ed25519 conversion".into()))?;
    let u = mont.mul_mod(&num, &den_inv);

    let u_be = u.to_be_bytes(32);
    let mut u_le = [0u8; 32];
    for (i, b) in u_be.iter().rev().enumerate() {
        u_le[i] = *b;
    }
    Ok(u_le)
}
