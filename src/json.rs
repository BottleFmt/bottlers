//! JSON encoding of bottles (draft §7), matching pybottle: byte fields are
//! base64url **without** padding; `hdr`/`dst`/`sig` are omitted when empty;
//! `typ` is omitted when zero.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ciborium::value::Value;
use serde_json::{Map, Value as Json};

use crate::bottle::{Bottle, HeaderValue, MessageFormat, MessageRecipient, MessageSignature};
use crate::error::{BottleError, Result};
use std::collections::BTreeMap;

fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    // Tolerate optional padding, like pybottle's decoder.
    let trimmed = s.trim_end_matches('=');
    URL_SAFE_NO_PAD
        .decode(trimmed)
        .map_err(|e| BottleError::Json(format!("base64url: {e}")))
}

/// Encodes a [`Bottle`] as JSON bytes.
pub fn bottle_to_json(b: &Bottle) -> Result<Vec<u8>> {
    let mut obj = Map::new();
    obj.insert("msg".into(), Json::String(b64(&b.message)));
    obj.insert("fmt".into(), Json::from(b.format.as_i64()));

    if !b.header.is_empty() {
        obj.insert("hdr".into(), header_to_json(&b.header)?);
    }
    if let Some(recipients) = &b.recipients
        && !recipients.is_empty()
    {
        obj.insert(
            "dst".into(),
            Json::Array(recipients.iter().map(recipient_to_json).collect()),
        );
    }
    if let Some(signatures) = &b.signatures
        && !signatures.is_empty()
    {
        obj.insert(
            "sig".into(),
            Json::Array(signatures.iter().map(signature_to_json).collect()),
        );
    }

    serde_json::to_vec(&Json::Object(obj)).map_err(|e| BottleError::Json(e.to_string()))
}

/// Decodes a JSON-encoded [`Bottle`].
pub fn bottle_from_json(data: &[u8]) -> Result<Bottle> {
    let v: Json = serde_json::from_slice(data).map_err(|e| BottleError::Json(e.to_string()))?;
    let obj = v
        .as_object()
        .ok_or_else(|| BottleError::Json("bottle must be a JSON object".into()))?;

    let message = match obj.get("msg") {
        Some(Json::String(s)) => unb64(s)?,
        _ => Vec::new(),
    };
    let format = MessageFormat::from_i64(obj.get("fmt").and_then(Json::as_i64).unwrap_or(0))?;

    let header = match obj.get("hdr") {
        Some(Json::Object(m)) => json_to_header(m)?,
        _ => BTreeMap::new(),
    };

    let recipients = match obj.get("dst") {
        Some(Json::Array(items)) if !items.is_empty() => Some(
            items
                .iter()
                .map(recipient_from_json)
                .collect::<Result<Vec<_>>>()?,
        ),
        _ => None,
    };
    let signatures = match obj.get("sig") {
        Some(Json::Array(items)) if !items.is_empty() => Some(
            items
                .iter()
                .map(signature_from_json)
                .collect::<Result<Vec<_>>>()?,
        ),
        _ => None,
    };

    Ok(Bottle {
        header,
        message,
        format,
        recipients,
        signatures,
    })
}

fn recipient_to_json(r: &MessageRecipient) -> Json {
    let mut m = Map::new();
    m.insert("key".into(), Json::String(b64(&r.recipient)));
    m.insert("dat".into(), Json::String(b64(&r.data)));
    if r.typ != 0 {
        m.insert("typ".into(), Json::from(r.typ));
    }
    Json::Object(m)
}

fn signature_to_json(s: &MessageSignature) -> Json {
    let mut m = Map::new();
    m.insert("key".into(), Json::String(b64(&s.signer)));
    m.insert("dat".into(), Json::String(b64(&s.data)));
    if s.typ != 0 {
        m.insert("typ".into(), Json::from(s.typ));
    }
    Json::Object(m)
}

fn recipient_from_json(v: &Json) -> Result<MessageRecipient> {
    let m = v
        .as_object()
        .ok_or_else(|| BottleError::Json("recipient".into()))?;
    Ok(MessageRecipient {
        typ: m.get("typ").and_then(Json::as_i64).unwrap_or(0),
        recipient: unb64(str_field(m, "key")?)?,
        data: unb64(str_field(m, "dat")?)?,
    })
}

fn signature_from_json(v: &Json) -> Result<MessageSignature> {
    let m = v
        .as_object()
        .ok_or_else(|| BottleError::Json("signature".into()))?;
    Ok(MessageSignature {
        typ: m.get("typ").and_then(Json::as_i64).unwrap_or(0),
        signer: unb64(str_field(m, "key")?)?,
        data: unb64(str_field(m, "dat")?)?,
    })
}

fn str_field<'a>(m: &'a Map<String, Json>, key: &str) -> Result<&'a str> {
    m.get(key)
        .and_then(Json::as_str)
        .ok_or_else(|| BottleError::Json(format!("missing string field {key}")))
}

// --- header (CBOR Value <-> JSON Value) ---------------------------------

fn header_to_json(header: &BTreeMap<String, HeaderValue>) -> Result<Json> {
    let mut m = Map::new();
    for (k, v) in header {
        m.insert(k.clone(), cbor_value_to_json(v)?);
    }
    Ok(Json::Object(m))
}

fn json_to_header(obj: &Map<String, Json>) -> Result<BTreeMap<String, HeaderValue>> {
    let mut m = BTreeMap::new();
    for (k, v) in obj {
        m.insert(k.clone(), json_to_cbor_value(v));
    }
    Ok(m)
}

fn cbor_value_to_json(v: &Value) -> Result<Json> {
    Ok(match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Integer(i) => Json::from(i128::from(*i) as i64),
        Value::Float(f) => serde_json::Number::from_f64(*f)
            .map(Json::Number)
            .unwrap_or(Json::Null),
        Value::Text(t) => Json::String(t.clone()),
        Value::Bytes(b) => Json::String(b64(b)),
        Value::Array(items) => Json::Array(
            items
                .iter()
                .map(cbor_value_to_json)
                .collect::<Result<_>>()?,
        ),
        Value::Map(entries) => {
            let mut m = Map::new();
            for (k, val) in entries {
                let key = match k {
                    Value::Text(t) => t.clone(),
                    _ => return Err(BottleError::Json("non-string header map key".into())),
                };
                m.insert(key, cbor_value_to_json(val)?);
            }
            Json::Object(m)
        }
        _ => Json::Null,
    })
}

fn json_to_cbor_value(v: &Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Integer(i.into())
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Json::String(s) => Value::Text(s.clone()),
        Json::Array(items) => Value::Array(items.iter().map(json_to_cbor_value).collect()),
        Json::Object(obj) => Value::Map(
            obj.iter()
                .map(|(k, v)| (Value::Text(k.clone()), json_to_cbor_value(v)))
                .collect(),
        ),
    }
}
