//! Group memberships (gobottle `membership.go`).
//!
//! Encoded as an integer-keyed CBOR map (keys 1..7). The signature covers the
//! canonical CBOR of the structure with the signature field set to null.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::cbor;
use crate::error::{BottleError, Result};
use crate::key::PrivateKey;

/// A membership of a subject in a group.
#[derive(Clone, Debug)]
pub struct Membership {
    /// The subject (member) primary key; cleared once stored on an IDCard.
    pub subject: Option<Vec<u8>>,
    /// The group key (group identification).
    pub key: Vec<u8>,
    /// Membership status (e.g. "valid", "suspended").
    pub status: String,
    /// Update time, Unix seconds.
    pub issued: i64,
    /// Subject information (name, etc.).
    pub info: Option<BTreeMap<String, String>>,
    /// The key that generated the signature.
    pub sign_key: Option<Vec<u8>>,
    /// The signature over the structure (with this field null) by the group key.
    pub signature: Option<Vec<u8>>,
}

impl Membership {
    /// Creates a new "valid" membership for `subject` in group `key`.
    pub fn new(subject: Vec<u8>, key: Vec<u8>, issued: i64) -> Self {
        Membership {
            subject: Some(subject),
            key,
            status: "valid".to_string(),
            issued,
            info: Some(BTreeMap::new()),
            sign_key: None,
            signature: None,
        }
    }

    fn entries(&self, include_signature: bool) -> Vec<(Value, Value)> {
        let opt_bytes = |b: &Option<Vec<u8>>| match b {
            None => Value::Null,
            Some(v) => Value::Bytes(v.clone()),
        };
        let info = match &self.info {
            None => Value::Null,
            Some(m) => cbor::canonical_map(
                m.iter()
                    .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                    .collect(),
            ),
        };
        vec![
            (Value::Integer(1.into()), opt_bytes(&self.subject)),
            (Value::Integer(2.into()), Value::Bytes(self.key.clone())),
            (Value::Integer(3.into()), Value::Text(self.status.clone())),
            (Value::Integer(4.into()), Value::Integer(self.issued.into())),
            (Value::Integer(5.into()), info),
            (Value::Integer(6.into()), opt_bytes(&self.sign_key)),
            (
                Value::Integer(7.into()),
                if include_signature {
                    opt_bytes(&self.signature)
                } else {
                    Value::Null
                },
            ),
        ]
    }

    pub(crate) fn to_value(&self) -> Value {
        cbor::canonical_map(self.entries(true))
    }

    /// The canonical bytes that are signed/verified (signature field nulled).
    pub fn signature_bytes(&self) -> Result<Vec<u8>> {
        cbor::to_vec(&cbor::canonical_map(self.entries(false)))
    }

    pub(crate) fn from_value(v: &Value) -> Result<Self> {
        let map = match v {
            Value::Map(entries) => {
                let mut m = BTreeMap::new();
                for (k, val) in entries {
                    m.insert(cbor::as_i64(k)?, val.clone());
                }
                m
            }
            _ => return Err(BottleError::Malformed("membership must be a map".into())),
        };
        let opt_bytes = |key: i64| -> Result<Option<Vec<u8>>> {
            match map.get(&key) {
                None | Some(Value::Null) => Ok(None),
                Some(v) => Ok(Some(cbor::as_bytes(v)?)),
            }
        };
        let info = match map.get(&5) {
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
        let status = match map.get(&3) {
            Some(Value::Text(t)) => t.clone(),
            _ => return Err(BottleError::Malformed("membership status missing".into())),
        };
        Ok(Membership {
            subject: opt_bytes(1)?,
            key: map
                .get(&2)
                .map(cbor::as_bytes)
                .transpose()?
                .ok_or_else(|| BottleError::Malformed("membership key missing".into()))?,
            status,
            issued: map.get(&4).map(cbor::as_i64).transpose()?.unwrap_or(0),
            info,
            sign_key: opt_bytes(6)?,
            signature: opt_bytes(7)?,
        })
    }

    /// Signs the membership with the group's signing key.
    pub fn sign(&mut self, key: &PrivateKey) -> Result<()> {
        if self.subject.is_none() {
            return Err(BottleError::Malformed(
                "subject must be set before signing".into(),
            ));
        }
        self.sign_key = Some(key.public_pkix()?);
        let buf = self.signature_bytes()?;
        self.signature = Some(crate::sign::sign(key, &buf)?);
        Ok(())
    }

    /// Verifies the membership signature. When `group_id` is `None`, the signing
    /// key must equal the group key.
    pub fn verify(&self, group_id: Option<&crate::idcard::IDCard>) -> Result<()> {
        if self.subject.is_none() {
            return Err(BottleError::Malformed(
                "subject must be set before verifying".into(),
            ));
        }
        let sign_key = self
            .sign_key
            .as_ref()
            .ok_or_else(|| BottleError::Malformed("missing signing key".into()))?;
        match group_id {
            None => {
                if sign_key != &self.key {
                    return Err(BottleError::Malformed("invalid signing key".into()));
                }
            }
            Some(id) => {
                if self.key != id.self_key {
                    return Err(BottleError::Malformed("invalid group id".into()));
                }
                let now = 0; // purpose check without expiry context
                let fit = id.keys_for("sign", now);
                let want = crate::pkix::parse_public_key(sign_key)?;
                let want_pkix = crate::pkix::marshal_public_key(&want)?;
                if !fit
                    .iter()
                    .filter_map(|k| crate::pkix::marshal_public_key(k).ok())
                    .any(|k| k == want_pkix)
                {
                    return Err(BottleError::KeyUnfit);
                }
            }
        }
        let sig = self
            .signature
            .as_ref()
            .ok_or_else(|| BottleError::Malformed("missing signature".into()))?;
        let buf = self.signature_bytes()?;
        crate::sign::verify_pkix(sign_key, &buf, sig)
    }
}
