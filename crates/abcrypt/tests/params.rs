// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use abcrypt::Params;

// Generated using `abcrypt` crate version 0.1.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.abcrypt");

#[test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[test]
fn memory_cost() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.memory_cost(), 32);
}

#[test]
fn time_cost() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.time_cost(), 3);
}

#[test]
fn parallelism() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.parallelism(), 4);
}

#[cfg(feature = "serde")]
#[test]
fn serialize() {
    use serde_test::{assert_ser_tokens, Token};

    assert_ser_tokens(
        &Params::new(TEST_DATA_ENC).unwrap(),
        &[
            Token::Struct {
                name: "Params",
                len: 3,
            },
            Token::Str("memoryCost"),
            Token::U32(32),
            Token::Str("timeCost"),
            Token::U32(3),
            Token::Str("parallelism"),
            Token::U32(4),
            Token::StructEnd,
        ],
    );
}

#[cfg(feature = "serde")]
#[test]
fn serialize_json() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(
        serde_json::to_string(&params).unwrap(),
        r#"{"memoryCost":32,"timeCost":3,"parallelism":4}"#
    );
}
