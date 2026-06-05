//! Post-quantum public-key parsing hook used by [`crate::pkix`]: tries ML-KEM
//! (encryption) and ML-DSA / SLH-DSA (signature) OIDs before falling through to
//! the classical SPKI parser.

use crate::error::Result;
use crate::key::PublicKey;

/// Attempts to parse a post-quantum public key from its SPKI. Returns
/// `Ok(None)` when the algorithm OID is not a post-quantum one.
pub(crate) fn try_parse_spki(
    alg_oid: &[u64],
    key_bytes: &[u8],
    der: &[u8],
) -> Result<Option<PublicKey>> {
    if let Some(k) = crate::mlkem::try_parse(alg_oid, key_bytes)? {
        return Ok(Some(PublicKey::MlKem(k)));
    }
    crate::pqsig::try_parse(alg_oid, key_bytes, der)
}
