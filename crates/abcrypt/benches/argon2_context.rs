// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]

extern crate test;

use abcrypt::Argon2;
use test::Bencher;

// Generated using `abcrypt` crate version 0.4.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/v1/argon2id/v0x13/data.txt.abcrypt");

#[bench]
fn params(b: &mut Bencher) {
    b.iter(|| Argon2::new(TEST_DATA_ENC));
}
