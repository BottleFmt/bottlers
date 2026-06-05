//! ML-KEM (FIPS 203) key-encapsulation, pure and X25519-hybrid, matching
//! gobottle's `mlkem.go`.
//!
//! Short-buffer envelope formats:
//! - pure (version 2): `0x02 || uvarint(ct_len) || ct || nonce || AES-256-GCM`,
//!   key = ML-KEM shared secret.
//! - hybrid (version 1): `0x01 || uvarint(eph_x25519_pkix_len) || eph_x25519_pkix
//!   || uvarint(ct_len) || ct || nonce || AES-256-GCM`,
//!   key = `SHA-256(x25519_shared || mlkem_secret)`.

use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::mlkem::{
    MlKem768Ciphertext, MlKem768DecapsKey, MlKem768EncapsKey, MlKem1024Ciphertext,
    MlKem1024DecapsKey, MlKem1024EncapsKey,
};
use purecrypto::rng::OsRng;

use crate::aead::{self, NONCE_SIZE};
use crate::cbor::{append_uvarint, read_uvarint};
use crate::error::{BottleError, Result};
use crate::hash::sha256;
use crate::key::PublicKey;
use crate::pkix;

/// ML-KEM parameter set.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MlKemVariant {
    /// ML-KEM-768.
    V768,
    /// ML-KEM-1024.
    V1024,
}

#[derive(Clone)]
enum Encaps {
    K768(MlKem768EncapsKey),
    K1024(MlKem1024EncapsKey),
}

enum Decaps {
    K768(MlKem768DecapsKey),
    K1024(MlKem1024DecapsKey),
}

/// An ML-KEM public (encapsulation) key, optionally hybrid with X25519.
#[derive(Clone)]
pub struct MlKemPublic {
    variant: MlKemVariant,
    ek: Encaps,
    x25519: Option<[u8; 32]>,
}

/// An ML-KEM private (decapsulation) key, optionally hybrid with X25519.
pub struct MlKemPrivate {
    variant: MlKemVariant,
    dk: Decaps,
    x25519: Option<X25519PrivateKey>,
}

impl MlKemPublic {
    /// Returns the parameter set.
    pub fn variant(&self) -> MlKemVariant {
        self.variant
    }
    /// Returns true if this is a hybrid (X25519 + ML-KEM) key.
    pub fn is_hybrid(&self) -> bool {
        self.x25519.is_some()
    }

    fn ek_bytes(&self) -> Vec<u8> {
        match &self.ek {
            Encaps::K768(k) => k.to_bytes().to_vec(),
            Encaps::K1024(k) => k.to_bytes().to_vec(),
        }
    }
}

impl MlKemPrivate {
    /// Generates a fresh ML-KEM key pair (hybrid adds an X25519 key).
    pub fn generate(variant: MlKemVariant, hybrid: bool) -> Self {
        let (dk, _) = match variant {
            MlKemVariant::V768 => {
                let (d, _e) = MlKem768DecapsKey::generate(&mut OsRng);
                (Decaps::K768(d), ())
            }
            MlKemVariant::V1024 => {
                let (d, _e) = MlKem1024DecapsKey::generate(&mut OsRng);
                (Decaps::K1024(d), ())
            }
        };
        let x25519 = hybrid.then(|| X25519PrivateKey::generate(&mut OsRng));
        MlKemPrivate { variant, dk, x25519 }
    }

    /// Returns the matching public key.
    pub fn public(&self) -> MlKemPublic {
        let ek = match &self.dk {
            Decaps::K768(d) => Encaps::K768(d.encapsulation_key()),
            Decaps::K1024(d) => Encaps::K1024(d.encapsulation_key()),
        };
        MlKemPublic {
            variant: self.variant,
            ek,
            x25519: self.x25519.as_ref().map(|x| x.public_key()),
        }
    }
}

/// Encrypts the content key for an ML-KEM recipient.
pub fn encrypt(data: &[u8], remote: &MlKemPublic) -> Result<Vec<u8>> {
    if remote.is_hybrid() {
        hybrid_encrypt(data, remote)
    } else {
        pure_encrypt(data, remote)
    }
}

fn mlkem_encapsulate(ek: &Encaps) -> (Vec<u8>, [u8; 32]) {
    match ek {
        Encaps::K768(k) => {
            let (ct, ss) = k.encapsulate(&mut OsRng);
            (ct.to_bytes().to_vec(), ss)
        }
        Encaps::K1024(k) => {
            let (ct, ss) = k.encapsulate(&mut OsRng);
            (ct.to_bytes().to_vec(), ss)
        }
    }
}

fn pure_encrypt(data: &[u8], remote: &MlKemPublic) -> Result<Vec<u8>> {
    let (ct, secret) = mlkem_encapsulate(&remote.ek);
    let mut nonce = [0u8; NONCE_SIZE];
    use purecrypto::rng::RngCore;
    OsRng.fill_bytes(&mut nonce);
    let mut out = vec![2u8];
    append_uvarint(&mut out, ct.len() as u64);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&aead::seal(&secret, &nonce, data));
    Ok(out)
}

fn hybrid_encrypt(data: &[u8], remote: &MlKemPublic) -> Result<Vec<u8>> {
    use purecrypto::rng::RngCore;
    let peer_x = remote
        .x25519
        .ok_or_else(|| BottleError::Crypto("hybrid key missing X25519".into()))?;
    let eph = X25519PrivateKey::generate(&mut OsRng);
    let x_shared = eph
        .diffie_hellman(&peer_x)
        .map_err(|e| BottleError::Crypto(format!("X25519: {e:?}")))?;
    let (ct, mlkem_secret) = mlkem_encapsulate(&remote.ek);
    let combined = combine(&x_shared, &mlkem_secret);

    let eph_pkix = pkix::marshal_public_key(&PublicKey::X25519(eph.public_key()))?;
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);

    let mut out = vec![1u8];
    append_uvarint(&mut out, eph_pkix.len() as u64);
    out.extend_from_slice(&eph_pkix);
    append_uvarint(&mut out, ct.len() as u64);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&aead::seal(&combined, &nonce, data));
    Ok(out)
}

/// Decrypts an ML-KEM envelope with the recipient private key.
pub fn decrypt(data: &[u8], priv_key: &MlKemPrivate) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(BottleError::Malformed("empty ML-KEM message".into()));
    }
    match data[0] {
        1 => {
            // hybrid
            let x_priv = priv_key
                .x25519
                .as_ref()
                .ok_or_else(|| BottleError::Crypto("non-hybrid key for hybrid message".into()))?;
            let (eph_pkix, rest) = read_chunk(&data[1..])?;
            let (ct, rest) = read_chunk(rest)?;
            let eph_pub = match pkix::parse_public_key(eph_pkix)? {
                PublicKey::X25519(u) => u,
                _ => return Err(BottleError::Malformed("expected X25519 ephemeral".into())),
            };
            let x_shared = x_priv
                .diffie_hellman(&eph_pub)
                .map_err(|e| BottleError::Crypto(format!("X25519: {e:?}")))?;
            let mlkem_secret = mlkem_decapsulate(&priv_key.dk, ct)?;
            let combined = combine(&x_shared, &mlkem_secret);
            open_tail(rest, &combined)
        }
        2 => {
            // pure
            let (ct, rest) = read_chunk(&data[1..])?;
            let secret = mlkem_decapsulate(&priv_key.dk, ct)?;
            open_tail(rest, &secret)
        }
        v => Err(BottleError::Malformed(format!(
            "unsupported ML-KEM message version {v}"
        ))),
    }
}

fn mlkem_decapsulate(dk: &Decaps, ct: &[u8]) -> Result<[u8; 32]> {
    match dk {
        Decaps::K768(d) => {
            let ct: [u8; 1088] = ct
                .try_into()
                .map_err(|_| BottleError::Malformed("bad ML-KEM-768 ciphertext".into()))?;
            Ok(d.decapsulate(&MlKem768Ciphertext::from_bytes(ct)))
        }
        Decaps::K1024(d) => {
            let ct: [u8; 1568] = ct
                .try_into()
                .map_err(|_| BottleError::Malformed("bad ML-KEM-1024 ciphertext".into()))?;
            Ok(d.decapsulate(&MlKem1024Ciphertext::from_bytes(ct)))
        }
    }
}

fn combine(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(a.len() + b.len());
    buf.extend_from_slice(a);
    buf.extend_from_slice(b);
    sha256(&buf)
}

fn read_chunk(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, n) = read_uvarint(data)?;
    let len = len as usize;
    if len > 1 << 20 || data.len() < n + len {
        return Err(BottleError::Malformed("bad ML-KEM length prefix".into()));
    }
    Ok((&data[n..n + len], &data[n + len..]))
}

fn open_tail(rest: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if rest.len() < NONCE_SIZE {
        return Err(BottleError::Malformed("ML-KEM tail too short".into()));
    }
    let (nonce, ct) = rest.split_at(NONCE_SIZE);
    aead::open(key, nonce, ct)
}

// --- PKIX --------------------------------------------------------------

const OID_MLKEM_768: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 4, 2];
const OID_MLKEM_1024: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 4, 3];
const OID_COMPOSITE_768_X25519: &[u64] = &[1, 3, 6, 1, 4, 1, 60545, 1, 1, 1];
const OID_COMPOSITE_1024_X25519: &[u64] = &[1, 3, 6, 1, 4, 1, 60545, 1, 1, 2];

/// Marshals an ML-KEM public key to PKIX/DER (pure or composite hybrid),
/// matching gobottle's encoding.
pub fn marshal_spki(key: &MlKemPublic) -> Result<Vec<u8>> {
    use purecrypto::der::{encode_bit_string, encode_sequence, oid_tlv};
    if let Some(x) = &key.x25519 {
        let oid = match key.variant {
            MlKemVariant::V768 => OID_COMPOSITE_768_X25519,
            MlKemVariant::V1024 => OID_COMPOSITE_1024_X25519,
        };
        // composite = SEQUENCE { BITSTRING x25519, BITSTRING mlkem }
        let composite = encode_sequence(
            &[encode_bit_string(x), encode_bit_string(&key.ek_bytes())].concat(),
        );
        let algid = encode_sequence(&oid_tlv(oid));
        Ok(encode_sequence(
            &[algid, encode_bit_string(&composite)].concat(),
        ))
    } else {
        let oid = match key.variant {
            MlKemVariant::V768 => OID_MLKEM_768,
            MlKemVariant::V1024 => OID_MLKEM_1024,
        };
        let algid = encode_sequence(&oid_tlv(oid));
        Ok(encode_sequence(
            &[algid, encode_bit_string(&key.ek_bytes())].concat(),
        ))
    }
}

/// Attempts to parse an ML-KEM public key from an SPKI's algorithm OID and the
/// raw BIT STRING contents. Returns `Ok(None)` if not an ML-KEM OID.
pub fn try_parse(alg_oid: &[u64], key_bytes: &[u8]) -> Result<Option<MlKemPublic>> {
    let (variant, hybrid) = if alg_oid == OID_MLKEM_768 {
        (MlKemVariant::V768, false)
    } else if alg_oid == OID_MLKEM_1024 {
        (MlKemVariant::V1024, false)
    } else if alg_oid == OID_COMPOSITE_768_X25519 {
        (MlKemVariant::V768, true)
    } else if alg_oid == OID_COMPOSITE_1024_X25519 {
        (MlKemVariant::V1024, true)
    } else {
        return Ok(None);
    };

    let (ek_bytes, x25519) = if hybrid {
        let (x, mlkem) = parse_composite(key_bytes)?;
        (mlkem, Some(x))
    } else {
        (key_bytes.to_vec(), None)
    };

    let ek = make_encaps(variant, &ek_bytes)?;
    Ok(Some(MlKemPublic { variant, ek, x25519 }))
}

fn make_encaps(variant: MlKemVariant, bytes: &[u8]) -> Result<Encaps> {
    match variant {
        MlKemVariant::V768 => {
            let b: [u8; 1184] = bytes
                .try_into()
                .map_err(|_| BottleError::Pkix("bad ML-KEM-768 key length".into()))?;
            Ok(Encaps::K768(MlKem768EncapsKey::from_bytes(b)))
        }
        MlKemVariant::V1024 => {
            let b: [u8; 1568] = bytes
                .try_into()
                .map_err(|_| BottleError::Pkix("bad ML-KEM-1024 key length".into()))?;
            Ok(Encaps::K1024(MlKem1024EncapsKey::from_bytes(b)))
        }
    }
}

/// Parses the composite `SEQUENCE { BITSTRING x25519, BITSTRING mlkem }`.
fn parse_composite(data: &[u8]) -> Result<([u8; 32], Vec<u8>)> {
    let (tag, body, _) = crate::pkix::read_tlv(data)?;
    if tag != 0x30 {
        return Err(BottleError::Pkix("composite key must be a SEQUENCE".into()));
    }
    let (t1, b1, rest) = crate::pkix::read_tlv(body)?;
    if t1 != 0x03 || b1.is_empty() {
        return Err(BottleError::Pkix("expected X25519 BIT STRING".into()));
    }
    let x_bytes = &b1[1..];
    if x_bytes.len() != 32 {
        return Err(BottleError::Pkix("X25519 component must be 32 bytes".into()));
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(x_bytes);

    let (t2, b2, _) = crate::pkix::read_tlv(rest)?;
    if t2 != 0x03 || b2.is_empty() {
        return Err(BottleError::Pkix("expected ML-KEM BIT STRING".into()));
    }
    Ok((x, b2[1..].to_vec()))
}
