// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use abcrypt::{argon2::Params, Decryptor, Encryptor};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[test]
fn success() {
    {
        let cipher =
            Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
                .unwrap();
        let mut buf = vec![u8::default(); cipher.out_len()];
        cipher.encrypt(&mut buf);
        assert_ne!(buf, TEST_DATA);
        assert_eq!(buf.len(), TEST_DATA.len() + 156);

        let plaintext = Decryptor::new(&buf, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }

    {
        let ciphertext =
            Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
                .map(Encryptor::encrypt_to_vec)
                .unwrap();
        assert_ne!(ciphertext, TEST_DATA);
        assert_eq!(ciphertext.len(), TEST_DATA.len() + 156);

        let plaintext = Decryptor::new(&ciphertext, PASSPHRASE)
            .and_then(Decryptor::decrypt_to_vec)
            .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
}

#[test]
#[should_panic(expected = "source slice length (30) does not match destination slice length (29)")]
fn invalid_output_length() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = vec![u8::default(); cipher.out_len() - 1];
    cipher.encrypt(&mut buf);
}

#[test]
fn minimum_output_length() {
    let cipher =
        Encryptor::with_params(&[], PASSPHRASE, Params::new(32, 3, 4, None).unwrap()).unwrap();
    assert_eq!(cipher.out_len(), 156);
    let ciphertext = cipher.encrypt_to_vec();
    assert_eq!(ciphertext.len(), 156);
}

#[test]
fn magic_number() {
    let ciphertext =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(Encryptor::encrypt_to_vec)
            .unwrap();
    assert_eq!(&ciphertext[..7], b"abcrypt");
}

#[test]
fn version() {
    let ciphertext =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(Encryptor::encrypt_to_vec)
            .unwrap();
    assert_eq!(ciphertext[7], 0);
}

#[test]
fn m_cost() {
    let ciphertext =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(Encryptor::encrypt_to_vec)
            .unwrap();
    assert_eq!(&ciphertext[8..12], u32::to_le_bytes(32));
}

#[test]
fn t_cost() {
    let ciphertext =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(Encryptor::encrypt_to_vec)
            .unwrap();
    assert_eq!(&ciphertext[12..16], u32::to_le_bytes(3));
}

#[test]
fn p_cost() {
    let ciphertext =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(Encryptor::encrypt_to_vec)
            .unwrap();
    assert_eq!(&ciphertext[16..20], u32::to_le_bytes(4));
}

#[test]
fn out_len() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    assert_eq!(cipher.out_len(), 170);
}
