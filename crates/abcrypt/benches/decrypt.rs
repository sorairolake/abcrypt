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

use abcrypt::Decryptor;

const PASSPHRASE: &str = "passphrase";
// Generated using `abcrypt` crate version 0.1.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/data.txt.abcrypt");

#[bench]
fn decrypt(b: &mut Bencher) {
    b.iter(|| {
        Decryptor::new(&TEST_DATA_ENC, PASSPHRASE)
            .and_then(|c| c.decrypt_to_vec())
            .unwrap()
    });
}
