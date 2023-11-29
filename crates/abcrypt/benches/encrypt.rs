// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

extern crate test;

use test::Bencher;

use abcrypt::{argon2::Params, Encryptor};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("../tests/data/data.txt");

#[bench]
fn encrypt(b: &mut Bencher) {
    b.iter(|| {
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(|c| c.encrypt_to_vec())
            .unwrap()
    });
}
