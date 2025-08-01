// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]

extern crate test;

use abcrypt::{Encryptor, argon2::Params};
use test::Bencher;

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
