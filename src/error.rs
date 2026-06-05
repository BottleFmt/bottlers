//! Error type for the `bottlers` crate.

use core::fmt;

/// Errors returned by bottle operations.
#[derive(Debug)]
pub enum BottleError {
    /// No key in the keychain could open the bottle.
    NoAppropriateKey,
    /// A signature failed to verify.
    VerifyFailed,
    /// The requested key was not found in the keychain.
    KeyNotFound,
    /// The group was not found.
    GroupNotFound,
    /// The provided key was not fit for the requested purpose.
    KeyUnfit,
    /// Encryption was attempted without any valid recipient.
    EncryptNoRecipient,
    /// A key type was not supported by the requested operation.
    UnsupportedKey(&'static str),
    /// CBOR (de)serialization failed.
    Cbor(String),
    /// JSON (de)serialization failed.
    Json(String),
    /// A PKIX/DER encoding or parsing operation failed.
    Pkix(String),
    /// The bottle does not contain another bottle, or it is encrypted.
    NotABottle,
    /// A cryptographic primitive reported a failure.
    Crypto(String),
    /// The wire data was malformed.
    Malformed(String),
}

impl fmt::Display for BottleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BottleError::NoAppropriateKey => {
                write!(f, "no appropriate key available to open bottle")
            }
            BottleError::VerifyFailed => write!(f, "signature verification failed"),
            BottleError::KeyNotFound => write!(f, "the key was not found"),
            BottleError::GroupNotFound => write!(f, "the group was not found"),
            BottleError::KeyUnfit => write!(f, "the provided key was not fit"),
            BottleError::EncryptNoRecipient => write!(
                f,
                "cannot encrypt a message without at least one valid recipient"
            ),
            BottleError::UnsupportedKey(t) => write!(f, "unsupported key type {t}"),
            BottleError::Cbor(m) => write!(f, "cbor error: {m}"),
            BottleError::Json(m) => write!(f, "json error: {m}"),
            BottleError::Pkix(m) => write!(f, "pkix error: {m}"),
            BottleError::NotABottle => write!(
                f,
                "bottle does not contain another bottle or it is encrypted"
            ),
            BottleError::Crypto(m) => write!(f, "crypto error: {m}"),
            BottleError::Malformed(m) => write!(f, "malformed data: {m}"),
        }
    }
}

impl std::error::Error for BottleError {}

/// Convenience alias for results returning a [`BottleError`].
pub type Result<T> = core::result::Result<T, BottleError>;
