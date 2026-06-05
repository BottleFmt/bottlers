//! JSON encoding of bottles (draft §7). Full parity is completed in a later
//! phase; for now only the nested-bottle decode path used by [`crate::bottle`]
//! is wired up.

use crate::bottle::Bottle;
use crate::error::{BottleError, Result};

/// Decodes a JSON-encoded [`Bottle`].
pub fn bottle_from_json(_data: &[u8]) -> Result<Bottle> {
    Err(BottleError::Json("JSON bottle decoding not yet implemented".into()))
}
