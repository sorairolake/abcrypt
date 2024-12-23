// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]

extern crate test;

use abcrypt::Decryptor;
use test::Bencher;

const PASSPHRASE: &str = "passphrase";
// Generated using `abcrypt` crate version 0.4.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/v1/argon2id/v0x13/data.txt.abcrypt");

#[bench]
fn decrypt(b: &mut Bencher) {
    b.iter(|| {
        Decryptor::new(&TEST_DATA_ENC, PASSPHRASE)
            .and_then(|c| c.decrypt_to_vec())
            .unwrap()
    });
}
