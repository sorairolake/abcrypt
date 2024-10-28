// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]

extern crate test;

use abcrypt::Params;
use test::Bencher;

// Generated using `abcrypt` crate version 0.1.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/data.txt.abcrypt");

#[bench]
fn params(b: &mut Bencher) {
    b.iter(|| Params::new(TEST_DATA_ENC));
}
