//! Post-quantum signatures: ML-DSA (FIPS 204) and SLH-DSA (FIPS 205).
//!
//! Note on OIDs: gobottle marshals ML-DSA keys with the legacy IETF draft arc
//! `1.3.6.1.4.1.2.267.12.*`, **not** the NIST arc purecrypto uses. For wire
//! compatibility bottlers marshals/parses ML-DSA SPKI with gobottle's OIDs and
//! drives purecrypto's raw key bytes directly. SLH-DSA OIDs already match, so it
//! reuses purecrypto's SPKI codec.

use purecrypto::der::{encode_bit_string, encode_sequence, oid_tlv};
use purecrypto::mldsa::{MlDsa44PublicKey, MlDsa65PublicKey, MlDsa87PublicKey};
use purecrypto::slhdsa;

use crate::error::{BottleError, Result};
use crate::key::{PrivateKey, PublicKey};

/// gobottle ML-DSA OIDs (legacy IETF draft arc).
pub(crate) const OID_MLDSA_44: &[u64] = &[1, 3, 6, 1, 4, 1, 2, 267, 12, 4, 4];
pub(crate) const OID_MLDSA_65: &[u64] = &[1, 3, 6, 1, 4, 1, 2, 267, 12, 6, 5];
pub(crate) const OID_MLDSA_87: &[u64] = &[1, 3, 6, 1, 4, 1, 2, 267, 12, 8, 7];

fn mldsa_spki(oid: &[u64], key_bytes: &[u8]) -> Vec<u8> {
    let algid = encode_sequence(&oid_tlv(oid));
    encode_sequence(&[algid, encode_bit_string(key_bytes)].concat())
}

/// Marshals an ML-DSA / SLH-DSA public key, returning `None` for other keys.
pub(crate) fn marshal_spki(key: &PublicKey) -> Option<Vec<u8>> {
    match key {
        PublicKey::MlDsa44(k) => Some(mldsa_spki(OID_MLDSA_44, k.to_bytes())),
        PublicKey::MlDsa65(k) => Some(mldsa_spki(OID_MLDSA_65, k.to_bytes())),
        PublicKey::MlDsa87(k) => Some(mldsa_spki(OID_MLDSA_87, k.to_bytes())),
        PublicKey::SlhDsa(k) => Some(k.to_spki_der()),
        _ => None,
    }
}

/// Attempts to parse an ML-DSA / SLH-DSA public key from its algorithm OID and
/// raw key bytes (plus the full DER for SLH-DSA). Returns `Ok(None)` if the OID
/// is not a PQ-signature OID.
pub(crate) fn try_parse(alg_oid: &[u64], key_bytes: &[u8], der: &[u8]) -> Result<Option<PublicKey>> {
    if alg_oid == OID_MLDSA_44 {
        let k = MlDsa44PublicKey::from_bytes(key_bytes)
            .map_err(|e| BottleError::Pkix(format!("ML-DSA-44: {e:?}")))?;
        return Ok(Some(PublicKey::MlDsa44(k)));
    }
    if alg_oid == OID_MLDSA_65 {
        let k = MlDsa65PublicKey::from_bytes(key_bytes)
            .map_err(|e| BottleError::Pkix(format!("ML-DSA-65: {e:?}")))?;
        return Ok(Some(PublicKey::MlDsa65(k)));
    }
    if alg_oid == OID_MLDSA_87 {
        let k = MlDsa87PublicKey::from_bytes(key_bytes)
            .map_err(|e| BottleError::Pkix(format!("ML-DSA-87: {e:?}")))?;
        return Ok(Some(PublicKey::MlDsa87(k)));
    }
    // SLH-DSA OIDs are 2.16.840.1.101.3.4.3.{20..=31}.
    if alg_oid.len() == 9 && alg_oid[..8] == [2, 16, 840, 1, 101, 3, 4, 3] && (20..=31).contains(&alg_oid[8])
    {
        let set = slhdsa::ParamSet::from_oid(alg_oid)
            .ok_or_else(|| BottleError::Pkix("unknown SLH-DSA parameter set".into()))?;
        let k = slhdsa::PublicKey::from_spki_der(set, der)
            .map_err(|e| BottleError::Pkix(format!("SLH-DSA: {e:?}")))?;
        return Ok(Some(PublicKey::SlhDsa(k)));
    }
    Ok(None)
}

/// Signs `msg` with a PQ signing key (empty context), returning `None` for
/// non-PQ keys.
pub(crate) fn sign(key: &PrivateKey, msg: &[u8]) -> Option<Result<Vec<u8>>> {
    fn wrap<E: core::fmt::Debug>(r: core::result::Result<Vec<u8>, E>) -> Result<Vec<u8>> {
        r.map_err(|e| BottleError::Crypto(format!("PQ sign: {e:?}")))
    }
    let res = match key {
        PrivateKey::MlDsa44(k) => wrap(k.sign_deterministic(msg, &[])),
        PrivateKey::MlDsa65(k) => wrap(k.sign_deterministic(msg, &[])),
        PrivateKey::MlDsa87(k) => wrap(k.sign_deterministic(msg, &[])),
        PrivateKey::SlhDsa(k) => wrap(k.sign_deterministic(msg, &[])),
        _ => return None,
    };
    Some(res)
}

/// Verifies a PQ signature (empty context), returning `None` for non-PQ keys.
pub(crate) fn verify(key: &PublicKey, msg: &[u8], sig: &[u8]) -> Option<Result<()>> {
    let ok = match key {
        PublicKey::MlDsa44(k) => k.verify(sig, msg, &[]),
        PublicKey::MlDsa65(k) => k.verify(sig, msg, &[]),
        PublicKey::MlDsa87(k) => k.verify(sig, msg, &[]),
        PublicKey::SlhDsa(k) => k.verify(sig, msg, &[]),
        _ => return None,
    };
    Some(if ok {
        Ok(())
    } else {
        Err(BottleError::VerifyFailed)
    })
}
