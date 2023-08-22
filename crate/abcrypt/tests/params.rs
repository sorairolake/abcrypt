// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use scryptenc::Params;

// Generated using `scrypt` version 1.3.1.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.enc");

#[test]
fn success() {
    let params = Params::new(TEST_DATA_ENC);
    assert!(params.is_ok());
}

#[test]
fn log_n() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.log_n(), 10);
}

#[test]
fn n() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.n(), 1024);
}

#[test]
fn r() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.r(), 8);
}

#[test]
fn p() {
    let params = Params::new(TEST_DATA_ENC).unwrap();
    assert_eq!(params.p(), 1);
}
