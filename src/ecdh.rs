//! ECDH-based short-buffer encryption (gobottle's `ECDHEncrypt`/`ECDHDecrypt`).
//!
//! Wire format (version 0), shared by the P-256 and X25519 curves:
//!
//! ```text
//! 0x00 || uvarint(len pkix_eph_pub) || pkix_eph_pub || nonce(12) || AES-256-GCM
//! ```
//!
//! The symmetric key is `SHA-256(ecdh_shared_secret)`.

use purecrypto::ec::ecdh::EcdhPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPublicKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::rng::{OsRng, RngCore};

use crate::aead::{self, NONCE_SIZE};
use crate::cbor::{append_uvarint, read_uvarint};
use crate::error::{BottleError, Result};
use crate::hash::sha256;
use crate::key::{PrivateKey, PublicKey};
use crate::pkix;

fn random_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    nonce
}

fn envelope(eph_pub_pkix: &[u8], key: &[u8; 32], data: &[u8]) -> Vec<u8> {
    let nonce = random_nonce();
    let mut out = Vec::with_capacity(1 + eph_pub_pkix.len() + NONCE_SIZE + data.len() + 16);
    out.push(0); // version
    append_uvarint(&mut out, eph_pub_pkix.len() as u64);
    out.extend_from_slice(eph_pub_pkix);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&aead::seal(key, &nonce, data));
    out
}

/// Encrypts `data` for a P-256 recipient.
pub fn encrypt_p256(data: &[u8], remote: &EcdsaPublicKey) -> Result<Vec<u8>> {
    let eph = EcdhPrivateKey::generate(&mut OsRng);
    let secret = eph
        .diffie_hellman(remote)
        .map_err(|e| BottleError::Crypto(format!("ECDH: {e:?}")))?;
    let key = sha256(&secret);
    let eph_pub = eph.public_key();
    let eph_pkix = marshal_p256(&eph_pub)?;
    Ok(envelope(&eph_pkix, &key, data))
}

/// Encrypts `data` for an X25519 recipient (the 32-byte Montgomery u).
pub fn encrypt_x25519(data: &[u8], peer_u: &[u8; 32]) -> Result<Vec<u8>> {
    let eph = X25519PrivateKey::generate(&mut OsRng);
    let secret = eph
        .diffie_hellman(peer_u)
        .map_err(|e| BottleError::Crypto(format!("X25519: {e:?}")))?;
    let key = sha256(&secret);
    let eph_pkix = pkix::marshal_public_key(&PublicKey::X25519(eph.public_key()))?;
    Ok(envelope(&eph_pkix, &key, data))
}

/// Decrypts an ECDH envelope using the recipient's private key.
pub fn decrypt(data: &[u8], recipient: &PrivateKey) -> Result<Vec<u8>> {
    if data.is_empty() || data[0] != 0 {
        return Err(BottleError::Malformed("unsupported ECDH message version".into()));
    }
    let (len, consumed) = read_uvarint(&data[1..])?;
    let off = 1 + consumed;
    let len = len as usize;
    if len > 65536 || data.len() < off + len + NONCE_SIZE {
        return Err(BottleError::Malformed("malformed ECDH envelope".into()));
    }
    let eph_pub_pkix = &data[off..off + len];
    let nonce = &data[off + len..off + len + NONCE_SIZE];
    let ciphertext = &data[off + len + NONCE_SIZE..];

    let eph_pub = pkix::parse_public_key(eph_pub_pkix)?;

    let secret = match (recipient, &eph_pub) {
        (PrivateKey::Ecdsa(sk), PublicKey::Ecdsa(_)) => {
            let eph = eph_pub.as_p256()?;
            let ecdh = EcdhPrivateKey::from_bytes(&sk.to_bytes())
                .map_err(|e| BottleError::Crypto(format!("ECDH key: {e:?}")))?;
            ecdh.diffie_hellman(&eph)
                .map_err(|e| BottleError::Crypto(format!("ECDH: {e:?}")))?
        }
        (PrivateKey::X25519(sk), PublicKey::X25519(eph_u)) => sk
            .diffie_hellman(eph_u)
            .map_err(|e| BottleError::Crypto(format!("X25519: {e:?}")))?,
        (PrivateKey::Ed25519(sk), PublicKey::X25519(eph_u)) => {
            let x = crate::ed_convert::ed25519_private_to_x25519(sk);
            x.diffie_hellman(eph_u)
                .map_err(|e| BottleError::Crypto(format!("X25519: {e:?}")))?
        }
        _ => return Err(BottleError::UnsupportedKey("recipient/ephemeral curve mismatch")),
    };

    let key = sha256(&secret);
    aead::open(&key, nonce, ciphertext)
}

/// Marshals a P-256 ECDSA public key to PKIX/DER.
fn marshal_p256(pub_key: &EcdsaPublicKey) -> Result<Vec<u8>> {
    use purecrypto::ec::{BoxedEcdsaPublicKey, CurveId};
    let boxed = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, &pub_key.to_sec1())
        .map_err(|e| BottleError::Crypto(format!("P-256 marshal: {e:?}")))?;
    pkix::marshal_public_key(&PublicKey::Ecdsa(boxed))
}
