//! `bottlers` — a Rust implementation of the [Bottle] secure-container protocol,
//! built entirely on the [`purecrypto`] toolkit (no foreign crypto code).
//!
//! Bottle is a unified container supporting multi-recipient encryption, multiple
//! signatures, recursive nesting, and both classical and post-quantum
//! algorithms. The companion IDCard protocol provides cryptographic identity.
//!
//! This crate aims for byte-exact wire compatibility with the reference Go
//! implementation (`gobottle`) and the other BottleFmt libraries.
//!
//! [Bottle]: https://github.com/BottleFmt

#![forbid(unsafe_code)]

pub mod aead;
pub mod bottle;
pub mod cbor;
pub mod ecdh;
pub mod ed_convert;
pub mod error;
pub mod hash;
pub mod json;
pub mod key;
pub mod keychain;
pub mod memclr;
pub mod opener;
pub mod pkix;
pub mod pqkey;
pub mod seal;
pub mod short;
pub mod sign;

pub use bottle::{Bottle, HeaderValue, MessageFormat, MessageRecipient, MessageSignature};
pub use error::{BottleError, Result};
pub use key::{PrivateKey, PublicKey};
pub use keychain::Keychain;
pub use opener::{OpenResult, Opener};
