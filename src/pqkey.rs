//! Post-quantum key parsing hook. Filled in during the post-quantum phase;
//! for now it never matches, so PKIX parsing falls through to the classical
//! path.

use crate::error::Result;
use crate::key::PublicKey;

/// Attempts to parse a post-quantum public key from its SPKI. Returns
/// `Ok(None)` when the algorithm OID is not a post-quantum one.
pub(crate) fn try_parse_spki(
    _alg_oid: &[u64],
    _key_bytes: &[u8],
    _der: &[u8],
) -> Result<Option<PublicKey>> {
    Ok(None)
}
