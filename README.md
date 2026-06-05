# bottlers

A Rust implementation of the [Bottle](https://github.com/BottleFmt) secure-container
protocol, built entirely on the [`purecrypto`](https://github.com/KarpelesLab/purecrypto)
toolkit — no foreign crypto code.

Bottle is a unified container supporting multi-recipient encryption, multiple
signatures, recursive nesting, and both classical and post-quantum algorithms.
`bottlers` aims for byte-exact wire compatibility with the reference Go
implementation (`gobottle`) and the other BottleFmt libraries.

## Status

| Area | State |
|------|-------|
| CBOR wire format (byte-exact, validated against gobottle interop vectors) | ✅ |
| Encrypt / sign / open, Keychain, Opener | ✅ |
| RSA, ECDSA (P-256), Ed25519, X25519 (+ Ed25519→X25519) | ✅ |
| Post-quantum: ML-KEM (+hybrid), ML-DSA, SLH-DSA | 🚧 |
| IDCard / Membership | 🚧 |
| JSON encoding | 🚧 |

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
