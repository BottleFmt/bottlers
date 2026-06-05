//! PKIX (SubjectPublicKeyInfo) marshaling and parsing.
//!
//! Classical keys go through purecrypto's [`AnyPublicKey`]. X25519 has no
//! `AnyPublicKey` variant, so its SPKI (OID 1.3.101.110) is built and parsed by
//! hand. Post-quantum OIDs are handled in their own modules.

use purecrypto::der::{encode_bit_string, encode_sequence, oid_tlv};
use purecrypto::x509::AnyPublicKey;

use crate::error::{BottleError, Result};
use crate::key::PublicKey;

/// OID arc for X25519 (RFC 8410): 1.3.101.110.
const OID_X25519: &[u64] = &[1, 3, 101, 110];

/// Marshals a [`PublicKey`] to PKIX/DER SubjectPublicKeyInfo.
pub fn marshal_public_key(key: &PublicKey) -> Result<Vec<u8>> {
    match key {
        PublicKey::Rsa(k) => Ok(AnyPublicKey::Rsa(k.clone()).to_spki_der()),
        PublicKey::Ecdsa(k) => Ok(AnyPublicKey::Ecdsa(k.clone()).to_spki_der()),
        PublicKey::Ed25519(k) => Ok(AnyPublicKey::Ed25519(*k).to_spki_der()),
        PublicKey::X25519(u) => {
            let algid = encode_sequence(&oid_tlv(OID_X25519));
            let bits = encode_bit_string(u);
            let mut body = algid;
            body.extend_from_slice(&bits);
            Ok(encode_sequence(&body))
        }
        PublicKey::MlKem(k) => crate::mlkem::marshal_spki(k),
        PublicKey::MlDsa44(_)
        | PublicKey::MlDsa65(_)
        | PublicKey::MlDsa87(_)
        | PublicKey::SlhDsa(_) => {
            crate::pqsig::marshal_spki(key).ok_or(BottleError::UnsupportedKey("PQ marshal"))
        }
    }
}

/// Parses a PKIX/DER SubjectPublicKeyInfo into a [`PublicKey`].
pub fn parse_public_key(der: &[u8]) -> Result<PublicKey> {
    let (alg_oid, key_bytes) = parse_spki(der)?;

    if alg_oid == OID_X25519 {
        if key_bytes.len() != 32 {
            return Err(BottleError::Pkix("X25519 key must be 32 bytes".into()));
        }
        let mut u = [0u8; 32];
        u.copy_from_slice(&key_bytes);
        return Ok(PublicKey::X25519(u));
    }

    // Post-quantum OIDs (handled before purecrypto, which uses different ones).
    if let Some(pk) = crate::pqkey::try_parse_spki(&alg_oid, &key_bytes, der)? {
        return Ok(pk);
    }

    match AnyPublicKey::from_spki_der(der)
        .map_err(|e| BottleError::Pkix(format!("{e:?}")))?
    {
        AnyPublicKey::Rsa(k) => Ok(PublicKey::Rsa(k)),
        AnyPublicKey::Ecdsa(k) => Ok(PublicKey::Ecdsa(k)),
        AnyPublicKey::Ed25519(k) => Ok(PublicKey::Ed25519(k)),
        _ => Err(BottleError::UnsupportedKey("unsupported PKIX key type")),
    }
}

// --- minimal DER SPKI peeker --------------------------------------------

/// Reads a definite-length DER TLV from `data`, returning (tag, content,
/// remaining).
pub(crate) fn read_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if data.len() < 2 {
        return Err(BottleError::Pkix("truncated DER".into()));
    }
    let tag = data[0];
    let first = data[1];
    let (len, hdr) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 || data.len() < 2 + n {
            return Err(BottleError::Pkix("bad DER length".into()));
        }
        let mut len = 0usize;
        for &byte in &data[2..2 + n] {
            len = (len << 8) | byte as usize;
        }
        (len, 2 + n)
    };
    if data.len() < hdr + len {
        return Err(BottleError::Pkix("DER length exceeds buffer".into()));
    }
    Ok((tag, &data[hdr..hdr + len], &data[hdr + len..]))
}

/// Decodes a DER OID body into its arc form.
fn decode_oid(body: &[u8]) -> Result<Vec<u64>> {
    if body.is_empty() {
        return Err(BottleError::Pkix("empty OID".into()));
    }
    let mut arcs = Vec::new();
    arcs.push((body[0] / 40) as u64);
    arcs.push((body[0] % 40) as u64);
    let mut value = 0u64;
    for &b in &body[1..] {
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(value);
            value = 0;
        }
    }
    Ok(arcs)
}

/// Parses an SPKI, returning the algorithm OID arcs and the raw public-key bytes
/// (the BIT STRING contents minus the unused-bits prefix).
pub(crate) fn parse_spki(der: &[u8]) -> Result<(Vec<u64>, Vec<u8>)> {
    let (tag, body, rest) = read_tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(BottleError::Pkix("SPKI must be a single SEQUENCE".into()));
    }
    let (alg_tag, alg_body, after_alg) = read_tlv(body)?;
    if alg_tag != 0x30 {
        return Err(BottleError::Pkix("AlgorithmIdentifier must be a SEQUENCE".into()));
    }
    let (oid_tag, oid_body, _) = read_tlv(alg_body)?;
    if oid_tag != 0x06 {
        return Err(BottleError::Pkix("expected OID in AlgorithmIdentifier".into()));
    }
    let oid = decode_oid(oid_body)?;

    let (bit_tag, bit_body, _) = read_tlv(after_alg)?;
    if bit_tag != 0x03 || bit_body.is_empty() {
        return Err(BottleError::Pkix("expected BIT STRING".into()));
    }
    // First byte is the unused-bits count (always 0 for these keys).
    Ok((oid, bit_body[1..].to_vec()))
}
