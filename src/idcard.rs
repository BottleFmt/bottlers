//! IDCard and SubKey: cryptographic identity for a primary signing key.
//!
//! CBOR encoding uses integer-keyed maps (gobottle `cbor:"N,keyasint"`). Times
//! are encoded as plain CBOR integers of Unix seconds (fxamacker's default
//! `time.Time` mode). IDCard fields 1..6 are always present (nil slices/maps
//! encode as `null`); `SubKey.Expires` (key 3) is omitted when absent.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::bottle::Bottle;
use crate::cbor;
use crate::error::{BottleError, Result};
use crate::key::PrivateKey;
use crate::opener::Opener;
use crate::pkix;

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// A key listed inside an [`IDCard`], with its purposes and validity.
#[derive(Clone, Debug)]
pub struct SubKey {
    /// The subkey's public key, PKIX/DER encoded.
    pub key: Vec<u8>,
    /// Issuance (addition) time, Unix seconds.
    pub issued: i64,
    /// Optional expiration time, Unix seconds.
    pub expires: Option<i64>,
    /// Purposes (e.g. "sign", "decrypt").
    pub purposes: Vec<String>,
}

impl SubKey {
    /// Returns true if the subkey lists the given purpose.
    pub fn has_purpose(&self, purpose: &str) -> bool {
        self.purposes.iter().any(|p| p == purpose)
    }

    /// Adds purposes, keeping the list sorted and deduplicated.
    pub fn add_purpose(&mut self, purposes: &[&str]) {
        for p in purposes {
            if !self.has_purpose(p) {
                self.purposes.push((*p).to_string());
            }
        }
        self.purposes.sort();
    }

    fn to_value(&self) -> Value {
        let mut entries = vec![
            (Value::Integer(1.into()), Value::Bytes(self.key.clone())),
            (Value::Integer(2.into()), Value::Integer(self.issued.into())),
        ];
        if let Some(exp) = self.expires {
            entries.push((Value::Integer(3.into()), Value::Integer(exp.into())));
        }
        entries.push((
            Value::Integer(4.into()),
            Value::Array(
                self.purposes
                    .iter()
                    .map(|p| Value::Text(p.clone()))
                    .collect(),
            ),
        ));
        cbor::canonical_map(entries)
    }

    fn from_value(v: &Value) -> Result<Self> {
        let map = as_int_map(v)?;
        Ok(SubKey {
            key: cbor::as_bytes(get(&map, 1)?)?,
            issued: cbor::as_i64(get(&map, 2)?)?,
            expires: map.get(&3).map(cbor::as_i64).transpose()?,
            purposes: map
                .get(&4)
                .map(parse_string_array)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

/// A cryptographic identity for a primary key.
#[derive(Clone, Debug)]
pub struct IDCard {
    /// The owner's primary public key, PKIX/DER encoded (field 1).
    pub self_key: Vec<u8>,
    /// Issuance time, Unix seconds (field 2).
    pub issued: i64,
    /// Known subkeys (field 3).
    pub subkeys: Vec<SubKey>,
    /// Revoked subkeys (field 4).
    pub revoke: Option<Vec<SubKey>>,
    /// Group memberships (field 5).
    pub groups: Option<Vec<crate::membership::Membership>>,
    /// Self-defined metadata (field 6).
    pub meta: Option<BTreeMap<String, String>>,
}

impl IDCard {
    /// Creates a new IDCard for `key`'s public key, with the primary key listed
    /// as a "sign" subkey.
    pub fn new(key: &PrivateKey) -> Result<Self> {
        let pkix = key.public_pkix()?;
        let now = now_unix();
        Ok(IDCard {
            self_key: pkix.clone(),
            issued: now,
            subkeys: vec![SubKey {
                key: pkix,
                issued: now,
                expires: None,
                purposes: vec!["sign".to_string()],
            }],
            revoke: None,
            groups: None,
            meta: None,
        })
    }

    /// Returns the parsed public keys of all subkeys fit for `purpose` and not
    /// expired.
    pub fn keys_for(&self, purpose: &str, now: i64) -> Vec<crate::key::PublicKey> {
        let mut out = Vec::new();
        for sub in &self.subkeys {
            if !sub.has_purpose(purpose) {
                continue;
            }
            if let Some(exp) = sub.expires
                && exp <= now
            {
                continue;
            }
            if let Ok(pk) = pkix::parse_public_key(&sub.key) {
                out.push(pk);
            }
        }
        out
    }

    /// Finds the subkey matching the given PKIX public key.
    pub fn find_key(&self, pkix: &[u8]) -> Option<&SubKey> {
        self.subkeys.iter().find(|s| s.key == pkix)
    }

    /// Sets the purposes of a key (creating a subkey entry if needed).
    pub fn set_key_purposes(&mut self, pkix: Vec<u8>, purposes: &[&str]) {
        let mut sorted: Vec<String> = purposes.iter().map(|p| p.to_string()).collect();
        sorted.sort();
        if let Some(sub) = self.subkeys.iter_mut().find(|s| s.key == pkix) {
            sub.purposes = sorted;
        } else {
            self.subkeys.push(SubKey {
                key: pkix,
                issued: now_unix(),
                expires: None,
                purposes: sorted,
            });
        }
    }

    // --- CBOR ------------------------------------------------------------

    pub(crate) fn to_value(&self) -> Value {
        let opt_array = |list: &Option<Vec<SubKey>>| match list {
            None => Value::Null,
            Some(v) => Value::Array(v.iter().map(SubKey::to_value).collect()),
        };
        let groups = match &self.groups {
            None => Value::Null,
            Some(v) => Value::Array(v.iter().map(crate::membership::Membership::to_value).collect()),
        };
        let meta = match &self.meta {
            None => Value::Null,
            Some(m) => cbor::canonical_map(
                m.iter()
                    .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                    .collect(),
            ),
        };
        cbor::canonical_map(vec![
            (Value::Integer(1.into()), Value::Bytes(self.self_key.clone())),
            (Value::Integer(2.into()), Value::Integer(self.issued.into())),
            (
                Value::Integer(3.into()),
                Value::Array(self.subkeys.iter().map(SubKey::to_value).collect()),
            ),
            (Value::Integer(4.into()), opt_array(&self.revoke)),
            (Value::Integer(5.into()), groups),
            (Value::Integer(6.into()), meta),
        ])
    }

    /// Encodes the IDCard as CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        cbor::to_vec(&self.to_value())
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self> {
        let map = as_int_map(v)?;
        let subkeys = match map.get(&3) {
            Some(Value::Array(items)) => items
                .iter()
                .map(SubKey::from_value)
                .collect::<Result<Vec<_>>>()?,
            _ => Vec::new(),
        };
        let revoke = match map.get(&4) {
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(SubKey::from_value)
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => None,
        };
        let groups = match map.get(&5) {
            Some(Value::Array(items)) => Some(
                items
                    .iter()
                    .map(crate::membership::Membership::from_value)
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => None,
        };
        let meta = match map.get(&6) {
            Some(Value::Map(entries)) => {
                let mut m = BTreeMap::new();
                for (k, val) in entries {
                    if let (Value::Text(k), Value::Text(v)) = (k, val) {
                        m.insert(k.clone(), v.clone());
                    }
                }
                Some(m)
            }
            _ => None,
        };
        Ok(IDCard {
            self_key: cbor::as_bytes(get(&map, 1)?)?,
            issued: cbor::as_i64(get(&map, 2)?)?,
            subkeys,
            revoke,
            groups,
            meta,
        })
    }

    /// Decodes an IDCard from raw CBOR (without signature checking).
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        Self::from_value(&cbor::from_slice(data)?)
    }

    /// Signs the IDCard, returning a CBOR-encoded signed [`Bottle`] containing it.
    pub fn sign(&self, key: &PrivateKey) -> Result<Vec<u8>> {
        let mut bottle = Bottle::new(self.to_cbor()?).with_header("ct", Value::Text("idcard".into()));
        bottle.bottle_up()?;
        bottle.sign(key)?;
        bottle.to_cbor()
    }

    /// Parses a signed IDCard bottle, verifying it is signed by its own primary
    /// key.
    pub fn from_signed(data: &[u8]) -> Result<Self> {
        let (payload, info) = Opener::empty().open_cbor(data)?;
        let card = IDCard::from_cbor(&payload)?;
        if !info.signed_by_pkix(&card.self_key) {
            return Err(BottleError::VerifyFailed);
        }
        Ok(card)
    }
}

// --- helpers -------------------------------------------------------------

fn as_int_map(v: &Value) -> Result<BTreeMap<i64, Value>> {
    match v {
        Value::Map(entries) => {
            let mut m = BTreeMap::new();
            for (k, val) in entries {
                let key = cbor::as_i64(k)?;
                m.insert(key, val.clone());
            }
            Ok(m)
        }
        _ => Err(BottleError::Malformed("expected integer-keyed map".into())),
    }
}

fn get(map: &BTreeMap<i64, Value>, key: i64) -> Result<&Value> {
    map.get(&key)
        .ok_or_else(|| BottleError::Malformed(format!("missing map key {key}")))
}

fn parse_string_array(v: &Value) -> Result<Vec<String>> {
    match v {
        Value::Array(items) => items
            .iter()
            .map(|i| match i {
                Value::Text(t) => Ok(t.clone()),
                _ => Err(BottleError::Malformed("expected text in array".into())),
            })
            .collect(),
        Value::Null => Ok(Vec::new()),
        _ => Err(BottleError::Malformed("expected array of strings".into())),
    }
}
