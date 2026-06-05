# bottlers

[![crates.io](https://img.shields.io/crates/v/bottlers.svg)](https://crates.io/crates/bottlers)
[![docs.rs](https://img.shields.io/docsrs/bottlers)](https://docs.rs/bottlers)
[![CI](https://github.com/BottleFmt/bottlers/actions/workflows/ci.yml/badge.svg)](https://github.com/BottleFmt/bottlers/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust implementation of the [Bottle](https://github.com/BottleFmt) secure-container
protocol, built entirely on the [`purecrypto`](https://github.com/KarpelesLab/purecrypto)
toolkit — no foreign crypto code.

Bottle is a unified container supporting multi-recipient encryption, multiple
signatures, recursive nesting, and both classical and post-quantum algorithms.
`bottlers` aims for byte-exact wire compatibility with the reference Go
implementation (`gobottle`) and the other BottleFmt libraries.

## Status

Full feature parity with the Go reference (`gobottle`).

| Area | State |
|------|-------|
| CBOR wire format (byte-exact, validated against gobottle interop vectors) | ✅ |
| JSON encoding (base64url, validated against the spec / pybottle) | ✅ |
| Encrypt / sign / open, Keychain, Opener | ✅ |
| RSA, ECDSA (P-256), Ed25519, X25519 (+ Ed25519→X25519) | ✅ |
| Post-quantum: ML-KEM (+ X25519 hybrid), ML-DSA, SLH-DSA | ✅ |
| IDCard / SubKey / Membership | ✅ |

Cross-implementation interop is verified by tests that decrypt gobottle-produced
ECDH and Ed25519→X25519 ciphertexts, verify its ECDSA/Ed25519 signatures, and
re-encode its CBOR Bottle and IDCard vectors byte-for-byte.

## Example

```rust
use bottlers::{Bottle, Keychain, Opener, PrivateKey};
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::rng::OsRng;

let recipient = PrivateKey::Ecdsa(EcdsaPrivateKey::generate(&mut OsRng));

let mut bottle = Bottle::new(b"hello".to_vec());
bottle.encrypt(&[recipient.public()]).unwrap();
let cbor = bottle.to_cbor().unwrap();

let opener = Opener::new(Keychain::from_keys([recipient]).unwrap());
let (plaintext, _info) = opener.open_cbor(&cbor).unwrap();
assert_eq!(plaintext, b"hello");
```

## License

MIT — see [LICENSE](LICENSE).
