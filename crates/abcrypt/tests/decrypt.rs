// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use abcrypt::{
    Decryptor, Error, HEADER_SIZE, TAG_SIZE, argon2, blake2::digest::MacError, chacha20poly1305,
};

const PASSPHRASE: &str = "passphrase";
const TEST_DATA: &[u8] = include_bytes!("data/data.txt");
// Generated using `abcrypt` crate version 0.4.0.
const TEST_DATA_ENC: &[u8] = include_bytes!("data/v1/argon2id/v0x13/data.txt.abcrypt");

#[test]
fn success() {
    #[cfg(feature = "alloc")]
    {
        let cipher = Decryptor::new(
            &include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        let mut buf = [u8::default(); TEST_DATA.len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }
    #[cfg(feature = "alloc")]
    {
        let cipher = Decryptor::new(
            &include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        let mut buf = [u8::default(); TEST_DATA.len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }
    #[cfg(feature = "alloc")]
    {
        let cipher = Decryptor::new(
            &include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        let mut buf = [u8::default(); TEST_DATA.len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }
    #[cfg(feature = "alloc")]
    {
        let cipher = Decryptor::new(
            &include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        let mut buf = [u8::default(); TEST_DATA.len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }
    #[cfg(feature = "alloc")]
    {
        let cipher = Decryptor::new(
            &include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        let mut buf = [u8::default(); TEST_DATA.len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }
    {
        let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
        let mut buf = [u8::default(); TEST_DATA.len()];
        cipher.decrypt(&mut buf).unwrap();
        assert_eq!(buf, TEST_DATA);
    }
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
    let _ = cipher.decrypt(&mut buf);
}

#[test]
fn incorrect_passphrase() {
    let err = Decryptor::new(&TEST_DATA_ENC, "password").unwrap_err();
    assert_eq!(err, MacError.into());
}

#[test]
fn invalid_input_length() {
    {
        let data = [u8::default(); (HEADER_SIZE + TAG_SIZE) - 1];
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(err, Error::InvalidLength);
    }

    {
        let data = [u8::default(); HEADER_SIZE + TAG_SIZE];
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
fn unsupported_version() {
    let err = Decryptor::new(include_bytes!("data/v0/data.txt.abcrypt"), PASSPHRASE).unwrap_err();
    assert_eq!(err, Error::UnsupportedVersion(0));
}

#[test]
fn unknown_version() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    data[7] = 2;
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(err, Error::UnknownVersion(2));
}

#[test]
fn invalid_params() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();

    {
        data[16..20].copy_from_slice(&u32::to_le_bytes(7));
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidArgon2Params(argon2::Error::MemoryTooLittle)
        );
    }

    {
        data[20..24].copy_from_slice(&u32::to_le_bytes(0));
        let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
        assert_eq!(
            err,
            Error::InvalidArgon2Params(argon2::Error::MemoryTooLittle)
        );
    }

    {
        data[24..28].copy_from_slice(&u32::pow(2, 24).to_le_bytes());
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
    data[16..20].copy_from_slice(&u32::to_le_bytes(argon2::Params::DEFAULT_M_COST));
    data[20..24].copy_from_slice(&u32::to_le_bytes(argon2::Params::DEFAULT_T_COST));
    data[24..28].copy_from_slice(&u32::to_le_bytes(argon2::Params::DEFAULT_P_COST));
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(
        err,
        Error::InvalidArgon2Context(argon2::Error::MemoryTooLittle)
    );
}

#[test]
fn invalid_header_mac() {
    let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let mut header_mac: [u8; 64] = data[84..148].try_into().unwrap();
    header_mac.reverse();
    data[84..148].copy_from_slice(&header_mac);
    let err = Decryptor::new(&data, PASSPHRASE).unwrap_err();
    assert_eq!(err, MacError.into());
}

#[test]
fn invalid_mac() {
    let data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
    let start_mac = data.len() - TAG_SIZE;
    let mut data = data;
    let mut mac: [u8; TAG_SIZE] = data[start_mac..].try_into().unwrap();
    mac.reverse();
    data[start_mac..].copy_from_slice(&mac);
    let cipher = Decryptor::new(&data, PASSPHRASE).unwrap();
    let mut buf = [u8::default(); TEST_DATA.len()];
    let err = cipher.decrypt(&mut buf).unwrap_err();
    assert_eq!(err, chacha20poly1305::Error.into());
}

#[test]
fn out_len() {
    let cipher = Decryptor::new(&TEST_DATA_ENC, PASSPHRASE).unwrap();
    assert_eq!(cipher.out_len(), TEST_DATA.len());
}

#[cfg(feature = "alloc")]
#[test]
fn success_convenience_function() {
    {
        let plaintext = abcrypt::decrypt(
            include_bytes!("data/v1/argon2d/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt::decrypt(
            include_bytes!("data/v1/argon2d/v0x13/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt::decrypt(
            include_bytes!("data/v1/argon2i/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt::decrypt(
            include_bytes!("data/v1/argon2i/v0x13/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt::decrypt(
            include_bytes!("data/v1/argon2id/v0x10/data.txt.abcrypt"),
            PASSPHRASE,
        )
        .unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
    {
        let plaintext = abcrypt::decrypt(TEST_DATA_ENC, PASSPHRASE).unwrap();
        assert_eq!(plaintext, TEST_DATA);
    }
}
