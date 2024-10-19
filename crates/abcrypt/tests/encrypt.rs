// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use abcrypt::{argon2::Params, Decryptor, Encryptor, HEADER_SIZE, TAG_SIZE};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");

#[cfg(feature = "alloc")]
#[test]
fn success() {
    let cipher = Encryptor::new(&TEST_DATA, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_ne!(buf, TEST_DATA);

    let params = abcrypt::Params::new(buf).unwrap();
    assert_eq!(params.memory_cost(), 19456);
    assert_eq!(params.time_cost(), 2);
    assert_eq!(params.parallelism(), 1);

    let cipher = Decryptor::new(&buf, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    cipher.decrypt(&mut buf).unwrap();
    assert_eq!(buf, TEST_DATA);
}

#[test]
fn success_with_params() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_ne!(buf, TEST_DATA);

    let params = abcrypt::Params::new(buf).unwrap();
    assert_eq!(params.memory_cost(), 32);
    assert_eq!(params.time_cost(), 3);
    assert_eq!(params.parallelism(), 4);

    let cipher = Decryptor::new(&buf, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    cipher.decrypt(&mut buf).unwrap();
    assert_eq!(buf, TEST_DATA);
}

#[cfg(feature = "alloc")]
#[test]
fn success_to_vec() {
    let ciphertext =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .map(|c| c.encrypt_to_vec())
            .unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(ciphertext.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = abcrypt::Params::new(&ciphertext).unwrap();
    assert_eq!(params.memory_cost(), 32);
    assert_eq!(params.time_cost(), 3);
    assert_eq!(params.parallelism(), 4);

    let plaintext = Decryptor::new(&ciphertext, PASSPHRASE)
        .and_then(|c| c.decrypt_to_vec())
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[test]
#[should_panic(expected = "source slice length (16) does not match destination slice length (15)")]
fn invalid_output_length() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE - 1];
    cipher.encrypt(&mut buf);
}

#[test]
fn minimum_output_length() {
    let cipher =
        Encryptor::with_params(&[], PASSPHRASE, Params::new(32, 3, 4, None).unwrap()).unwrap();
    assert_eq!(cipher.out_len(), HEADER_SIZE + TAG_SIZE);
    let mut buf = [u8::default(); HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
}

#[test]
fn magic_number() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[..7], b"abcrypt");
}

#[test]
fn version() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(buf[7], 0);
}

#[test]
fn memory_cost() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[8..12], u32::to_le_bytes(32));
}

#[test]
fn time_cost() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[12..16], u32::to_le_bytes(3));
}

#[test]
fn parallelism() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
    cipher.encrypt(&mut buf);
    assert_eq!(&buf[16..20], u32::to_le_bytes(4));
}

#[cfg(not(feature = "alloc"))]
#[test]
fn too_large_memory_blocks() {
    let err = Encryptor::with_params(
        &TEST_DATA,
        PASSPHRASE,
        Params::new(
            Params::DEFAULT_M_COST,
            Params::DEFAULT_T_COST,
            Params::DEFAULT_P_COST,
            None,
        )
        .unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        abcrypt::Error::InvalidArgon2Context(argon2::Error::MemoryTooLittle)
    );
}

#[test]
fn out_len() {
    let cipher =
        Encryptor::with_params(&TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    assert_eq!(cipher.out_len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);
}

#[cfg(feature = "alloc")]
#[test]
fn success_convenience_function() {
    let ciphertext = abcrypt::encrypt(TEST_DATA, PASSPHRASE).unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(ciphertext.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = abcrypt::Params::new(&ciphertext).unwrap();
    assert_eq!(params.memory_cost(), 19456);
    assert_eq!(params.time_cost(), 2);
    assert_eq!(params.parallelism(), 1);

    let plaintext = abcrypt::decrypt(ciphertext, PASSPHRASE).unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[cfg(feature = "alloc")]
#[test]
fn success_convenience_function_with_params() {
    let ciphertext =
        abcrypt::encrypt_with_params(TEST_DATA, PASSPHRASE, Params::new(32, 3, 4, None).unwrap())
            .unwrap();
    assert_ne!(ciphertext, TEST_DATA);
    assert_eq!(ciphertext.len(), TEST_DATA.len() + HEADER_SIZE + TAG_SIZE);

    let params = abcrypt::Params::new(&ciphertext).unwrap();
    assert_eq!(params.memory_cost(), 32);
    assert_eq!(params.time_cost(), 3);
    assert_eq!(params.parallelism(), 4);

    let plaintext = abcrypt::decrypt(ciphertext, PASSPHRASE).unwrap();
    assert_eq!(plaintext, TEST_DATA);
}
