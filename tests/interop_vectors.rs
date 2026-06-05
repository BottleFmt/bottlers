//! Byte-exact CBOR interop vectors, ported verbatim from gobottle's
//! `interop_test.go`. Each vector is base64-encoded CBOR produced by gobottle;
//! bottlers must decode it and re-encode to the identical bytes.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bottlers::Bottle;

fn decode(b64: &str) -> Vec<u8> {
    STANDARD.decode(b64).expect("valid base64")
}

/// Decodes the bottle, asserts it re-encodes to identical bytes.
fn assert_roundtrip(name: &str, b64: &str) -> Bottle {
    let raw = decode(b64);
    let bottle = Bottle::from_cbor(&raw).unwrap_or_else(|e| panic!("{name}: decode failed: {e}"));
    let re = bottle
        .to_cbor()
        .unwrap_or_else(|e| panic!("{name}: encode failed: {e}"));
    assert_eq!(
        re,
        raw,
        "{name}: re-encoded bytes differ\n  expected: {}\n  got:      {}",
        hex(&raw),
        hex(&re)
    );
    bottle
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

// --- CBOR edge-case vectors ---------------------------------------------

const EMPTY_MESSAGE_CLEARTEXT: &str = "haBAAPaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYRzBFAiB3/DuOTDB0laYp/j1MxHGdMaN5NUNQmjQEbdd6yo+iAQIhAOsLYnlcv3wvuhdIT+e5P4746a0sl6LIl8gOOwKq1Iz3";
const UNSIGNED_CLEARTEXT: &str = "haBQVW5zaWduZWQgbWVzc2FnZQD29g==";
const CBOR_NULL_PAYLOAD: &str = "haFiY3RkY2JvckH2APb2";
const CBOR_EMPTY_ARRAY_PAYLOAD: &str = "haFiY3RkY2JvckGAAPb2";
const CBOR_EMPTY_MAP_PAYLOAD: &str = "haFiY3RkY2JvckGgAPb2";
const CBOR_EMPTY_STRING_PAYLOAD: &str = "haFiY3RkY2JvckFgAPb2";
const SIGNED_EMPTY_HEADER: &str = "haBYGU1lc3NhZ2Ugd2l0aCBlbXB0eSBoZWFkZXIA9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIQDoHGQacPXpYkm05HM8sz0j0R+kxcahn8CrcneHb1kBXQIgHLaK9FhXVId9yPmvl1NF0K7yoOg9ypGvwJatsGHu0w8=";
const SINGLE_RECIPIENT_ENCRYPTED: &str = "haBZATiFoFg35zn2kpVD2fzY6Hp01M2l9cnpNFqelDbVGWP7LohxLN0y9ppOqN70a5DMi9IeL1ul4nLPXeTWIAKBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIoEQn7veaBj/RTUi1qMYYQgxJoMWBvLTMJRSLcwLlelv38NDoNgTRt8nNKjm/nBCY0ClkSPYv5tRVHPe2o2k65YmQBbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEku5qDv009WoDMMUzCNwSjfqtuEcZHtB+O79Eb3zKnKDoSffmYYwFQsCrlvPOKTXNuUDT13fjCZfXoNJ59KvtHCdjQqa0fyTtAKOfnwF/SM6xBEw4uPM8n4jYcCV5WaOqwxDgd1Nz59Nsl/uRwqepUchsOpQCXf+V+aM3ivYB9oGDAFhbMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE09oIghTDnluvtv0+NKMhTS2nfC3TzR4DWnZK7czzFPZSH6bJN5oMZCp5X7pfI4BbIyTVtGeRKg6GTpzzfE+KYFhHMEUCIF17mhvDS+JP/WJpxiBPNxodv3WK9rYdd5em61+mXqeIAiEAymnspZkwsWyLcKbwsA4fkscnOOuKU8lQ/U2sofCAVHk=";
const ED25519_SIGNED_EMPTY_RECIPIENTS: &str = "haBYHUVkMjU1MTkgc2lnbmVkLCBubyByZWNpcGllbnRzAPaBgwBYLDAqMAUGAytlcAMhAEy+j47jx0kyBtlF5iXxDLyREkqe8y6k53AQXOBJRPw+WEDO8suEMsxKYNtVAZtf9hqfmKpvjJV+fvcUoprVd65j1yB+qwxKCEGlH8t5ExP2NADKIw2rGc5CdCMYeFg5KE0I";
const CBOR_NESTED_PAYLOAD: &str = "haFiY3RkY2JvcleBomFhAWFipWFjAmFkA2FlBGFmBWFnBgD29g==";
const HEADER_WITH_VARIOUS_TYPES: &str =
    "haViY3RkanNvbmNpbnQYKmRib29s9WRudWxs9mZzdHJpbmdqaGVsbG8gdGVzdExUZXN0IG1lc3NhZ2UA9vY=";
const CBOR_INTEGER_BOUNDARIES: &str = "haFiY3RkY2JvclWJoBcYGBgYGP8ZAQAZ//8aAAEAAPYA9vY=";
const CBOR_BINARY_24_BYTES: &str = "haFiY3RkY2JvclgaWBhBQkNERUZHSElKS0xNTk9QUVJTVFVWV1gA9vY=";
const CBOR_ARRAY_24_ELEMENTS: &str = "haFiY3RkY2JvclgamBgAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcA9vY=";
const CBOR_INTEGER_KEY_MAP: &str = "haFiY3RkY2Jvck6lGQEBBQABAQICAzgkBAD29g==";
const SIGNED_BINARY_CONTENT: &str = "haBYIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fAPaBgwBYWzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNPaCIIUw55br7b9PjSjIU0tp3wt080eA1p2Su3M8xT2Uh+myTeaDGQqeV+6XyOAWyMk1bRnkSoOhk6c83xPimBYSDBGAiEA0tY/SQJvyj2vm02k8WDBK6tBU+rRKcDzSI2+FcSt030CIQD/pd2Rdbw4UrehHeiDgDP+znRJOyJTT4V/lgJyOconLA==";
const CBOR_NEGATIVE_INTEGERS: &str = "haFiY3RkY2Jvck6IICEiOCM4JDhnOP84/wD29g==";
const LARGE_HEADER_KEY: &str = "haJiY3RkY2JvcnhAYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWV2YWx1ZUH2APb2";

#[test]
fn cleartext_and_edge_vectors_roundtrip() {
    let vectors: &[(&str, &str)] = &[
        ("emptyMessageCleartext", EMPTY_MESSAGE_CLEARTEXT),
        ("unsignedCleartext", UNSIGNED_CLEARTEXT),
        ("cborNullPayload", CBOR_NULL_PAYLOAD),
        ("cborEmptyArrayPayload", CBOR_EMPTY_ARRAY_PAYLOAD),
        ("cborEmptyMapPayload", CBOR_EMPTY_MAP_PAYLOAD),
        ("cborEmptyStringPayload", CBOR_EMPTY_STRING_PAYLOAD),
        ("signedEmptyHeader", SIGNED_EMPTY_HEADER),
        ("singleRecipientEncrypted", SINGLE_RECIPIENT_ENCRYPTED),
        (
            "ed25519SignedEmptyRecipients",
            ED25519_SIGNED_EMPTY_RECIPIENTS,
        ),
        ("cborNestedPayload", CBOR_NESTED_PAYLOAD),
        ("headerWithVariousTypes", HEADER_WITH_VARIOUS_TYPES),
        ("cborIntegerBoundaries", CBOR_INTEGER_BOUNDARIES),
        ("cborBinary24Bytes", CBOR_BINARY_24_BYTES),
        ("cborArray24Elements", CBOR_ARRAY_24_ELEMENTS),
        ("cborIntegerKeyMap", CBOR_INTEGER_KEY_MAP),
        ("signedBinaryContent", SIGNED_BINARY_CONTENT),
        ("cborNegativeIntegers", CBOR_NEGATIVE_INTEGERS),
        ("largeHeaderKey", LARGE_HEADER_KEY),
    ];
    for (name, b64) in vectors {
        assert_roundtrip(name, b64);
    }
}

#[test]
fn unsigned_cleartext_payload() {
    let b = assert_roundtrip("unsignedCleartext", UNSIGNED_CLEARTEXT);
    assert_eq!(b.message, b"Unsigned message");
    assert!(b.signatures.is_none());
    assert_eq!(b.format, bottlers::MessageFormat::ClearText);
}

#[test]
fn nested_child_decodes() {
    // ed25519SignedEmptyRecipients has an explicit empty recipients array; ensure
    // null-vs-empty is preserved through the roundtrip (covered above) and that
    // the header-bearing nested bottles decode.
    let b = assert_roundtrip("cborNestedPayload", CBOR_NESTED_PAYLOAD);
    assert_eq!(b.format, bottlers::MessageFormat::ClearText);
    // header ct=cbor
    assert!(b.header.contains_key("ct"));
}
