//! The [`Bottle`] container and its CBOR wire encoding.
//!
//! A Bottle serializes as a fixed 5-element CBOR array (gobottle's
//! `cbor:",toarray"`):
//!
//! ```text
//! [ Header(map), Message(bstr), Format(int), Recipients(null|array), Signatures(null|array) ]
//! ```
//!
//! `Recipients` and `Signatures` are CBOR `null` (`0xf6`) when absent, matching
//! Go's `nil` slices. An explicit empty array (`0x80`) is also accepted on
//! decode.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::cbor;
use crate::error::{BottleError, Result};

/// A CBOR header value (`map[string]any` in gobottle).
pub type HeaderValue = Value;

/// The format of a [`Bottle`]'s message payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageFormat {
    /// The message is the raw payload.
    ClearText,
    /// The message is a CBOR-encoded nested [`Bottle`].
    CborBottle,
    /// The message is an AES-256-GCM encrypted CBOR [`Bottle`].
    Aes,
    /// The message is a JSON-encoded nested [`Bottle`].
    JsonBottle,
}

impl MessageFormat {
    /// Returns the on-wire integer for this format.
    pub fn as_i64(self) -> i64 {
        match self {
            MessageFormat::ClearText => 0,
            MessageFormat::CborBottle => 1,
            MessageFormat::Aes => 2,
            MessageFormat::JsonBottle => 3,
        }
    }

    /// Parses an on-wire format integer.
    pub fn from_i64(v: i64) -> Result<Self> {
        match v {
            0 => Ok(MessageFormat::ClearText),
            1 => Ok(MessageFormat::CborBottle),
            2 => Ok(MessageFormat::Aes),
            3 => Ok(MessageFormat::JsonBottle),
            other => Err(BottleError::Malformed(format!(
                "unrecognized message format {other}"
            ))),
        }
    }
}

/// A recipient able to decrypt an encrypted [`Bottle`].
#[derive(Clone, Debug)]
pub struct MessageRecipient {
    /// Recipient type tag (always 0 for now).
    pub typ: i64,
    /// The recipient's public key, PKIX/DER encoded.
    pub recipient: Vec<u8>,
    /// The encrypted content key payload, for this recipient only.
    pub data: Vec<u8>,
}

impl MessageRecipient {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Integer(self.typ.into()),
            Value::Bytes(self.recipient.clone()),
            Value::Bytes(self.data.clone()),
        ])
    }

    fn from_value(v: &Value) -> Result<Self> {
        let a = cbor::as_array(v)?;
        if a.len() != 3 {
            return Err(BottleError::Malformed("recipient must have 3 fields".into()));
        }
        Ok(MessageRecipient {
            typ: cbor::as_i64(&a[0])?,
            recipient: cbor::as_bytes(&a[1])?,
            data: cbor::as_bytes(&a[2])?,
        })
    }
}

/// A signature attached to a [`Bottle`].
#[derive(Clone, Debug)]
pub struct MessageSignature {
    /// Signature type tag (always 0 for now).
    pub typ: i64,
    /// The signer's public key, PKIX/DER encoded.
    pub signer: Vec<u8>,
    /// The signature bytes.
    pub data: Vec<u8>,
}

impl MessageSignature {
    fn to_value(&self) -> Value {
        Value::Array(vec![
            Value::Integer(self.typ.into()),
            Value::Bytes(self.signer.clone()),
            Value::Bytes(self.data.clone()),
        ])
    }

    fn from_value(v: &Value) -> Result<Self> {
        let a = cbor::as_array(v)?;
        if a.len() != 3 {
            return Err(BottleError::Malformed("signature must have 3 fields".into()));
        }
        Ok(MessageSignature {
            typ: cbor::as_i64(&a[0])?,
            signer: cbor::as_bytes(&a[1])?,
            data: cbor::as_bytes(&a[2])?,
        })
    }
}

/// A signed, optionally-encrypted message container.
#[derive(Clone, Debug)]
pub struct Bottle {
    /// Extra header values; not signed/encrypted unless the bottle is bottled up.
    pub header: BTreeMap<String, HeaderValue>,
    /// The message payload (interpretation depends on [`Bottle::format`]).
    pub message: Vec<u8>,
    /// The payload format.
    pub format: MessageFormat,
    /// Recipients, present only for encrypted bottles. `None` encodes as null.
    pub recipients: Option<Vec<MessageRecipient>>,
    /// Signatures. `None` encodes as null.
    pub signatures: Option<Vec<MessageSignature>>,
}

impl Bottle {
    /// Returns a new clean cleartext bottle wrapping `data`.
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Bottle {
            header: BTreeMap::new(),
            message: data.into(),
            format: MessageFormat::ClearText,
            recipients: None,
            signatures: None,
        }
    }

    /// Wraps `data`, treated as a CBOR-encoded nested bottle.
    pub fn as_cbor_bottle(data: impl Into<Vec<u8>>) -> Self {
        Bottle {
            header: BTreeMap::new(),
            message: data.into(),
            format: MessageFormat::CborBottle,
            recipients: None,
            signatures: None,
        }
    }

    /// Wraps `data`, treated as a JSON-encoded nested bottle.
    pub fn as_json_bottle(data: impl Into<Vec<u8>>) -> Self {
        Bottle {
            header: BTreeMap::new(),
            message: data.into(),
            format: MessageFormat::JsonBottle,
            recipients: None,
            signatures: None,
        }
    }

    /// Sets a header value, returning `self` for chaining.
    pub fn with_header(mut self, key: impl Into<String>, value: HeaderValue) -> Self {
        self.header.insert(key.into(), value);
        self
    }

    // --- CBOR ------------------------------------------------------------

    /// Builds the canonical CBOR [`Value`] tree for this bottle.
    pub(crate) fn to_value(&self) -> Value {
        let header_entries: Vec<(Value, Value)> = self
            .header
            .iter()
            .map(|(k, v)| (Value::Text(k.clone()), v.clone()))
            .collect();
        let header_val = cbor::canonical_map(header_entries);

        let recipients = match &self.recipients {
            None => Value::Null,
            Some(list) => Value::Array(list.iter().map(MessageRecipient::to_value).collect()),
        };
        let signatures = match &self.signatures {
            None => Value::Null,
            Some(list) => Value::Array(list.iter().map(MessageSignature::to_value).collect()),
        };

        Value::Array(vec![
            header_val,
            Value::Bytes(self.message.clone()),
            Value::Integer(self.format.as_i64().into()),
            recipients,
            signatures,
        ])
    }

    /// Encodes this bottle as CBOR.
    pub fn to_cbor(&self) -> Result<Vec<u8>> {
        cbor::to_vec(&self.to_value())
    }

    /// Parses a [`Bottle`] from a CBOR [`Value`].
    pub(crate) fn from_value(v: &Value) -> Result<Self> {
        let a = cbor::as_array(v)?;
        if a.len() != 5 {
            return Err(BottleError::Malformed(format!(
                "bottle must be a 5-element array, got {}",
                a.len()
            )));
        }

        let header = match &a[0] {
            Value::Map(entries) => {
                let mut m = BTreeMap::new();
                for (k, val) in entries {
                    let key = match k {
                        Value::Text(t) => t.clone(),
                        _ => {
                            return Err(BottleError::Malformed(
                                "header keys must be text strings".into(),
                            ));
                        }
                    };
                    m.insert(key, val.clone());
                }
                m
            }
            Value::Null => BTreeMap::new(),
            _ => return Err(BottleError::Malformed("header must be a map".into())),
        };

        let message = cbor::as_bytes(&a[1])?;
        let format = MessageFormat::from_i64(cbor::as_i64(&a[2])?)?;

        let recipients = match &a[3] {
            Value::Null => None,
            Value::Array(items) => Some(
                items
                    .iter()
                    .map(MessageRecipient::from_value)
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(BottleError::Malformed("recipients must be array or null".into())),
        };
        let signatures = match &a[4] {
            Value::Null => None,
            Value::Array(items) => Some(
                items
                    .iter()
                    .map(MessageSignature::from_value)
                    .collect::<Result<Vec<_>>>()?,
            ),
            _ => return Err(BottleError::Malformed("signatures must be array or null".into())),
        };

        Ok(Bottle {
            header,
            message,
            format,
            recipients,
            signatures,
        })
    }

    /// Decodes a [`Bottle`] from CBOR.
    pub fn from_cbor(data: &[u8]) -> Result<Self> {
        Self::from_value(&cbor::from_slice(data)?)
    }

    /// Encodes this bottle as JSON (draft §7).
    pub fn to_json(&self) -> Result<Vec<u8>> {
        crate::json::bottle_to_json(self)
    }

    /// Decodes a [`Bottle`] from JSON.
    pub fn from_json(data: &[u8]) -> Result<Self> {
        crate::json::bottle_from_json(data)
    }

    // --- structural operations ------------------------------------------

    /// Encodes the current bottle into itself, allowing extra layers to be
    /// applied (the reverse of [`Bottle::child`]).
    pub fn bottle_up(&mut self) -> Result<()> {
        let encoded = self.to_cbor()?;
        self.header = BTreeMap::new();
        self.message = encoded;
        self.format = MessageFormat::CborBottle;
        self.recipients = None;
        self.signatures = None;
        Ok(())
    }

    /// Returns the nested bottle contained in this one, if any.
    pub fn child(&self) -> Result<Bottle> {
        match self.format {
            MessageFormat::CborBottle => Bottle::from_cbor(&self.message),
            MessageFormat::JsonBottle => crate::json::bottle_from_json(&self.message),
            _ => Err(BottleError::NotABottle),
        }
    }

    /// Returns true if this is a clean (unsigned) bottle wrapping another bottle.
    pub fn is_clean_bottle(&self) -> bool {
        self.format == MessageFormat::CborBottle
            && self.signatures.as_ref().map(|s| s.is_empty()).unwrap_or(true)
    }
}
