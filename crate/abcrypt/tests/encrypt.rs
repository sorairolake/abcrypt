// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use scryptenc::{scrypt::Params, Decryptor, Encryptor};
use sha2::{Digest, Sha256};

const PASSWORD: &str = "password";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[test]
fn success() {
    {
        let cipher = Encryptor::with_params(
            TEST_DATA,
            PASSWORD,
            Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
        );
        let mut buf = vec![u8::default(); cipher.out_len()];
        cipher.encrypt(&mut buf);
        assert_ne!(buf, TEST_DATA);
        assert_eq!(buf.len(), TEST_DATA.len() + 128);

        let decrypted = Decryptor::new(buf, PASSWORD)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(decrypted, TEST_DATA);
    }

    {
        let encrypted = Encryptor::with_params(
            TEST_DATA,
            PASSWORD,
            Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
        )
        .encrypt_to_vec();
        assert_ne!(encrypted, TEST_DATA);
        assert_eq!(encrypted.len(), TEST_DATA.len() + 128);

        let decrypted = Decryptor::new(encrypted, PASSWORD)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(decrypted, TEST_DATA);
    }
}

#[test]
#[should_panic(expected = "source slice length (32) does not match destination slice length (31)")]
fn invalid_output_length() {
    let cipher = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    );
    let mut buf = vec![u8::default(); cipher.out_len() - 1];
    cipher.encrypt(&mut buf);
}

#[test]
fn magic_number() {
    let encrypted = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(&encrypted[..6], b"scrypt");
}

#[test]
fn version() {
    let encrypted = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(encrypted[6], 0);
}

#[test]
fn log_n() {
    let encrypted = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(encrypted[7], 10);
}

#[test]
fn r() {
    let encrypted = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(&encrypted[8..12], u32::to_be_bytes(8));
}

#[test]
fn p() {
    let encrypted = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    assert_eq!(&encrypted[12..16], u32::to_be_bytes(1));
}

#[test]
fn checksum() {
    let encrypted = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    )
    .encrypt_to_vec();
    let checksum = Sha256::digest(&encrypted[..48]);
    assert_eq!(&encrypted[48..64], &checksum[..16]);
}

#[test]
fn out_len() {
    let cipher = Encryptor::with_params(
        TEST_DATA,
        PASSWORD,
        Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap(),
    );
    assert_eq!(cipher.out_len(), 142);
}
