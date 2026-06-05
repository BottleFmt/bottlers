//! Low-level CBOR helpers: canonical map ordering, whole-value (de)serialization
//! and Go-compatible unsigned varints.
//!
//! The Bottle wire format is frozen against the interop vectors shipped by
//! gobottle, which encode map keys in **CBOR canonical (length-first) order**:
//! keys are sorted by the length of their encoded form first, then bytewise.
//! ciborium's [`Value::Map`] preserves insertion order, so we sort explicitly.

use crate::error::{BottleError, Result};
use ciborium::value::Value;

/// Encodes a single CBOR [`Value`] to bytes.
pub fn to_vec(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(value, &mut buf).map_err(|e| BottleError::Cbor(format!("{e:?}")))?;
    Ok(buf)
}

/// Decodes a single CBOR [`Value`] from bytes, rejecting trailing data.
pub fn from_slice(data: &[u8]) -> Result<Value> {
    let mut reader = data;
    let v: Value =
        ciborium::de::from_reader(&mut reader).map_err(|e| BottleError::Cbor(format!("{e:?}")))?;
    Ok(v)
}

/// Sorts the entries of a CBOR map into canonical (length-first) key order, in
/// place. Sorting is stable on the encoded key bytes.
pub fn canonical_sort(entries: &mut [(Value, Value)]) {
    entries.sort_by(|a, b| {
        let ka = to_vec(&a.0).unwrap_or_default();
        let kb = to_vec(&b.0).unwrap_or_default();
        ka.len().cmp(&kb.len()).then_with(|| ka.cmp(&kb))
    });
}

/// Builds a canonically-ordered CBOR map [`Value`] from the given entries.
pub fn canonical_map(mut entries: Vec<(Value, Value)>) -> Value {
    canonical_sort(&mut entries);
    Value::Map(entries)
}

// --- Value accessors -----------------------------------------------------

/// Extracts a byte string, accepting both definite byte strings and (for
/// robustness) text strings.
pub fn as_bytes(v: &Value) -> Result<Vec<u8>> {
    match v {
        Value::Bytes(b) => Ok(b.clone()),
        Value::Text(t) => Ok(t.as_bytes().to_vec()),
        _ => Err(BottleError::Malformed("expected byte string".into())),
    }
}

/// Extracts a signed integer.
pub fn as_i64(v: &Value) -> Result<i64> {
    match v {
        Value::Integer(i) => i128::from(*i)
            .try_into()
            .map_err(|_| BottleError::Malformed("integer out of range".into())),
        _ => Err(BottleError::Malformed("expected integer".into())),
    }
}

/// Returns the array elements of a CBOR array value.
pub fn as_array(v: &Value) -> Result<&Vec<Value>> {
    match v {
        Value::Array(a) => Ok(a),
        _ => Err(BottleError::Malformed("expected array".into())),
    }
}

// --- Go-compatible unsigned varint (LEB128) ------------------------------

/// Appends `value` to `out` as a Go `binary.AppendUvarint` (LEB128) encoding.
pub fn append_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// Reads a Go `binary.Uvarint` from the front of `data`, returning the value and
/// the number of bytes consumed.
pub fn read_uvarint(data: &[u8]) -> Result<(u64, usize)> {
    let mut x: u64 = 0;
    let mut shift = 0u32;
    for (i, &b) in data.iter().enumerate() {
        if b < 0x80 {
            if i > 9 || (i == 9 && b > 1) {
                return Err(BottleError::Malformed("uvarint overflow".into()));
            }
            return Ok((x | (u64::from(b) << shift), i + 1));
        }
        x |= u64::from(b & 0x7f) << shift;
        shift += 7;
    }
    Err(BottleError::Malformed("truncated uvarint".into()))
}
