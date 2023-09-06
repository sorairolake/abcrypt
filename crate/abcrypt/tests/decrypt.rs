// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use abcrypt::{argon2, blake2::digest::MacError, chacha20poly1305, Decryptor, Error};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");
// Generated using `abcrypt` crate version 0.1.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/data.txt.abcrypt");

#[test]
fn success() {
    let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    cipher.decrypt(&mut buf).unwrap();
    assert_eq!(buf, TEST_DATA);
}

#[cfg(feature = "alloc")]
#[test]
fn success_to_vec() {
    let plaintext = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE)
        .and_then(|c| c.decrypt_to_vec())
        .unwrap();
    assert_eq!(plaintext, TEST_DATA);
}

#[test]
#[should_panic(expected = "source slice length (14) does not match destination slice length (15)")]
fn invalid_output_length() {
    let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len() + 1];
    cipher.decrypt(&mut buf).unwrap();
}

#[test]
fn incorrect_passphrase() {
    let err = Decryptor::new(&TEST_DATA_ENC, "password").unwrap_err();
    assert_eq!(err, Error::InvalidHeaderMac(MacError));
}

#[test]
fn invalid_input_length() {
    {
        let data = [u8::default(); 155];
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(err, Error::InvalidLength);
    }

    {
        let data = [u8::default(); 156];
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(err, Error::InvalidMagicNumber);
    }
}

#[test]
fn invalid_magic_number() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[0] = u32::from('b').try_into().unwrap();
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(err, Error::InvalidMagicNumber);
}

#[test]
fn unknown_version() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[7] = 1;
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(err, Error::UnknownVersion(1));
}

#[test]
fn invalid_params() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();

    {
        data[8..12].copy_from_slice(&u32::to_le_bytes(7));
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidArgon2Params(argon2::Error::MemoryTooLittle)
        );
    }

    {
        data[12..16].copy_from_slice(&u32::to_le_bytes(0));
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidArgon2Params(argon2::Error::MemoryTooLittle)
        );
    }

    {
        data[16..20].copy_from_slice(&u32::pow(2, 24).to_le_bytes());
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidArgon2Params(argon2::Error::MemoryTooLittle)
        );
    }
}

#[cfg(not(feature = "alloc"))]
#[test]
fn too_large_memory_blocks() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[8..12].copy_from_slice(&u32::to_le_bytes(abcrypt::argon2::Params::DEFAULT_M_COST));
    data[12..16].copy_from_slice(&u32::to_le_bytes(abcrypt::argon2::Params::DEFAULT_T_COST));
    data[16..20].copy_from_slice(&u32::to_le_bytes(abcrypt::argon2::Params::DEFAULT_P_COST));
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidArgon2Context(argon2::Error::MemoryTooLittle)
    );
}

#[test]
fn invalid_header_mac() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let mut header_mac: [u8; 64] = data[76..140].try_into().unwrap();
    header_mac.reverse();
    data[76..140].copy_from_slice(&header_mac);
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(err, Error::InvalidHeaderMac(MacError));
}

#[test]
fn invalid_mac() {
    let data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let start_mac = data.len() - 16;
    let mut data = data;
    let mut mac: [u8; 16] = data[start_mac..].try_into().unwrap();
    mac.reverse();
    data[start_mac..].copy_from_slice(&mac);
    let cipher = Decryptor::new(&data, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    let err = cipher.decrypt(&mut buf).unwrap_err();
    assert_eq!(err, Error::InvalidMac(chacha20poly1305::Error));
}

#[test]
fn out_len() {
    let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
    assert_eq!(cipher.out_len(), TEST_DATA.len());
}
