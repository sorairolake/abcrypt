// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

use std::{ptr::NonNull, slice};

use abcrypt::{
    argon2::{Algorithm, Params},
    Encryptor,
};

use crate::ErrorCode;

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` and write to `out`.
///
/// This uses the recommended Argon2 parameters according to the OWASP Password
/// Storage Cheat Sheet. This also uses Argon2id as the Argon2 type and version
/// 0x13 as the Argon2 version.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - The Argon2 context is invalid.
/// - One of the parameters is null.
///
/// # Safety
///
/// Behavior is undefined if any of the following violates the safety conditions
/// of `slice::from_raw_parts`:
///
/// - `plaintext` and `plaintext_len`.
/// - `passphrase` and `passphrase_len`.
/// - `out` and `out_len`.
#[no_mangle]
pub unsafe extern "C-unwind" fn abcrypt_encrypt(
    plaintext: Option<NonNull<u8>>,
    plaintext_len: usize,
    passphrase: Option<NonNull<u8>>,
    passphrase_len: usize,
    out: Option<NonNull<u8>>,
    out_len: usize,
) -> ErrorCode {
    let Some(plaintext) = plaintext else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `plaintext` is not a null pointer.
    let plaintext = unsafe { slice::from_raw_parts(plaintext.as_ptr(), plaintext_len) };
    let Some(passphrase) = passphrase else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `passphrase` is not a null pointer.
    let passphrase = unsafe { slice::from_raw_parts(passphrase.as_ptr(), passphrase_len) };
    let cipher = match Encryptor::new(&plaintext, passphrase) {
        Ok(c) => c,
        Err(err) => {
            return err.into();
        }
    };

    let Some(out) = out else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `out` is not a null pointer.
    let out = unsafe { slice::from_raw_parts_mut(out.as_ptr(), out_len) };
    cipher.encrypt(out);
    ErrorCode::Ok
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified Argon2 parameters and write to
/// `out`.
///
/// This uses Argon2id as the Argon2 type and version 0x13 as the Argon2
/// version.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
/// - One of the parameters is null.
///
/// # Safety
///
/// Behavior is undefined if any of the following violates the safety conditions
/// of `slice::from_raw_parts`:
///
/// - `plaintext` and `plaintext_len`.
/// - `passphrase` and `passphrase_len`.
/// - `out` and `out_len`.
#[no_mangle]
pub unsafe extern "C-unwind" fn abcrypt_encrypt_with_params(
    plaintext: Option<NonNull<u8>>,
    plaintext_len: usize,
    passphrase: Option<NonNull<u8>>,
    passphrase_len: usize,
    out: Option<NonNull<u8>>,
    out_len: usize,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> ErrorCode {
    let Some(plaintext) = plaintext else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `plaintext` is not a null pointer.
    let plaintext = unsafe { slice::from_raw_parts(plaintext.as_ptr(), plaintext_len) };
    let Some(passphrase) = passphrase else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `passphrase` is not a null pointer.
    let passphrase = unsafe { slice::from_raw_parts(passphrase.as_ptr(), passphrase_len) };
    let Ok(params) = Params::new(memory_cost, time_cost, parallelism, None) else {
        return ErrorCode::InvalidArgon2Params;
    };
    let cipher = match Encryptor::with_params(&plaintext, passphrase, params) {
        Ok(c) => c,
        Err(err) => {
            return err.into();
        }
    };

    let Some(out) = out else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `out` is not a null pointer.
    let out = unsafe { slice::from_raw_parts_mut(out.as_ptr(), out_len) };
    cipher.encrypt(out);
    ErrorCode::Ok
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified Argon2 type, Argon2 version and
/// Argon2 parameters and write to `out`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - The Argon2 type is invalid.
/// - The Argon2 version is invalid.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
/// - One of the parameters is null.
///
/// # Safety
///
/// Behavior is undefined if any of the following violates the safety conditions
/// of `slice::from_raw_parts`:
///
/// - `plaintext` and `plaintext_len`.
/// - `passphrase` and `passphrase_len`.
/// - `out` and `out_len`.
#[no_mangle]
pub unsafe extern "C-unwind" fn abcrypt_encrypt_with_context(
    plaintext: Option<NonNull<u8>>,
    plaintext_len: usize,
    passphrase: Option<NonNull<u8>>,
    passphrase_len: usize,
    out: Option<NonNull<u8>>,
    out_len: usize,
    argon2_type: u32,
    argon2_version: u32,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> ErrorCode {
    let Some(plaintext) = plaintext else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `plaintext` is not a null pointer.
    let plaintext = unsafe { slice::from_raw_parts(plaintext.as_ptr(), plaintext_len) };
    let Some(passphrase) = passphrase else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `passphrase` is not a null pointer.
    let passphrase = unsafe { slice::from_raw_parts(passphrase.as_ptr(), passphrase_len) };
    let argon2_type = match argon2_type {
        0 => Algorithm::Argon2d,
        1 => Algorithm::Argon2i,
        2 => Algorithm::Argon2id,
        _ => return ErrorCode::InvalidArgon2Type,
    };
    let Ok(argon2_version) = argon2_version.try_into() else {
        return ErrorCode::InvalidArgon2Version;
    };
    let Ok(params) = Params::new(memory_cost, time_cost, parallelism, None) else {
        return ErrorCode::InvalidArgon2Params;
    };
    let cipher = match Encryptor::with_context(
        &plaintext,
        passphrase,
        argon2_type,
        argon2_version,
        params,
    ) {
        Ok(c) => c,
        Err(err) => {
            return err.into();
        }
    };

    let Some(out) = out else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `out` is not a null pointer.
    let out = unsafe { slice::from_raw_parts_mut(out.as_ptr(), out_len) };
    cipher.encrypt(out);
    ErrorCode::Ok
}

#[cfg(test)]
mod tests {
    use abcrypt::{argon2::Version, Argon2};

    use super::*;
    use crate::{abcrypt_decrypt, HEADER_SIZE, TAG_SIZE};

    const PASSPHRASE: &str = "passphrase";
    const TEST_DATA: &[u8] = include_bytes!("../tests/data/data.txt");

    #[test]
    fn success() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_ne!(ciphertext, TEST_DATA);

        let argon2 = Argon2::new(ciphertext).unwrap();
        assert_eq!(argon2.variant(), Algorithm::Argon2id);
        assert_eq!(argon2.version(), Version::V0x13);

        let params = abcrypt::Params::new(ciphertext).unwrap();
        assert_eq!(params.memory_cost(), 19456);
        assert_eq!(params.time_cost(), 2);
        assert_eq!(params.parallelism(), 1);

        let mut plaintext = [u8::default(); TEST_DATA.len()];
        assert_ne!(plaintext, TEST_DATA);
        let code = unsafe {
            abcrypt_decrypt(
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(plaintext, TEST_DATA);
    }

    #[test]
    fn success_with_params() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_ne!(ciphertext, TEST_DATA);

        let argon2 = Argon2::new(ciphertext).unwrap();
        assert_eq!(argon2.variant(), Algorithm::Argon2id);
        assert_eq!(argon2.version(), Version::V0x13);

        let params = abcrypt::Params::new(ciphertext).unwrap();
        assert_eq!(params.memory_cost(), 32);
        assert_eq!(params.time_cost(), 3);
        assert_eq!(params.parallelism(), 4);

        let mut plaintext = [u8::default(); TEST_DATA.len()];
        assert_ne!(plaintext, TEST_DATA);
        let code = unsafe {
            abcrypt_decrypt(
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(plaintext, TEST_DATA);
    }

    #[test]
    fn success_with_context() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_context(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                1,
                0x10,
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_ne!(ciphertext, TEST_DATA);

        let argon2 = Argon2::new(ciphertext).unwrap();
        assert_eq!(argon2.variant(), Algorithm::Argon2i);
        assert_eq!(argon2.version(), Version::V0x10);

        let params = abcrypt::Params::new(ciphertext).unwrap();
        assert_eq!(params.memory_cost(), 32);
        assert_eq!(params.time_cost(), 3);
        assert_eq!(params.parallelism(), 4);

        let mut plaintext = [u8::default(); TEST_DATA.len()];
        assert_ne!(plaintext, TEST_DATA);
        let code = unsafe {
            abcrypt_decrypt(
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(plaintext, TEST_DATA);
    }

    #[test]
    #[should_panic(
        expected = "source slice length (16) does not match destination slice length (15)"
    )]
    fn invalid_output_length() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE - 1];
        let _ = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
    }

    #[test]
    fn minimum_output_length() {
        let mut plaintext = [];
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
    }

    #[test]
    fn magic_number() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(&ciphertext[..7], b"abcrypt");
    }

    #[test]
    fn version() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(ciphertext[7], 1);
    }

    #[test]
    fn argon2_type() {
        {
            let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
            let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
            let code = unsafe {
                abcrypt_encrypt_with_context(
                    NonNull::new(plaintext.as_mut_ptr()),
                    plaintext.len(),
                    NonNull::new(passphrase.as_mut_ptr()),
                    passphrase.len(),
                    NonNull::new(ciphertext.as_mut_ptr()),
                    ciphertext.len(),
                    0,
                    0x13,
                    32,
                    3,
                    4,
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(&ciphertext[8..12], u32::to_le_bytes(0));

            let argon2 = Argon2::new(ciphertext).unwrap();
            assert_eq!(argon2.variant(), Algorithm::Argon2d);
        }
        {
            let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
            let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
            let code = unsafe {
                abcrypt_encrypt_with_context(
                    NonNull::new(plaintext.as_mut_ptr()),
                    plaintext.len(),
                    NonNull::new(passphrase.as_mut_ptr()),
                    passphrase.len(),
                    NonNull::new(ciphertext.as_mut_ptr()),
                    ciphertext.len(),
                    1,
                    0x13,
                    32,
                    3,
                    4,
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(&ciphertext[8..12], u32::to_le_bytes(1));

            let argon2 = Argon2::new(ciphertext).unwrap();
            assert_eq!(argon2.variant(), Algorithm::Argon2i);
        }
        {
            let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
            let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
            let code = unsafe {
                abcrypt_encrypt_with_context(
                    NonNull::new(plaintext.as_mut_ptr()),
                    plaintext.len(),
                    NonNull::new(passphrase.as_mut_ptr()),
                    passphrase.len(),
                    NonNull::new(ciphertext.as_mut_ptr()),
                    ciphertext.len(),
                    2,
                    0x13,
                    32,
                    3,
                    4,
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(&ciphertext[8..12], u32::to_le_bytes(2));

            let argon2 = Argon2::new(ciphertext).unwrap();
            assert_eq!(argon2.variant(), Algorithm::Argon2id);
        }
    }

    #[test]
    fn argon2_version() {
        {
            let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
            let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
            let code = unsafe {
                abcrypt_encrypt_with_context(
                    NonNull::new(plaintext.as_mut_ptr()),
                    plaintext.len(),
                    NonNull::new(passphrase.as_mut_ptr()),
                    passphrase.len(),
                    NonNull::new(ciphertext.as_mut_ptr()),
                    ciphertext.len(),
                    2,
                    0x10,
                    32,
                    3,
                    4,
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(&ciphertext[12..16], u32::to_le_bytes(0x10));

            let argon2 = Argon2::new(ciphertext).unwrap();
            assert_eq!(argon2.version(), Version::V0x10);
        }
        {
            let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
            let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
            let code = unsafe {
                abcrypt_encrypt_with_context(
                    NonNull::new(plaintext.as_mut_ptr()),
                    plaintext.len(),
                    NonNull::new(passphrase.as_mut_ptr()),
                    passphrase.len(),
                    NonNull::new(ciphertext.as_mut_ptr()),
                    ciphertext.len(),
                    2,
                    0x13,
                    32,
                    3,
                    4,
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(&ciphertext[12..16], u32::to_le_bytes(0x13));

            let argon2 = Argon2::new(ciphertext).unwrap();
            assert_eq!(argon2.version(), Version::V0x13);
        }
    }

    #[test]
    fn memory_cost() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(&ciphertext[16..20], u32::to_le_bytes(32));

        let params = abcrypt::Params::new(ciphertext).unwrap();
        assert_eq!(params.memory_cost(), 32);
    }

    #[test]
    fn time_cost() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(&ciphertext[20..24], u32::to_le_bytes(3));

        let params = abcrypt::Params::new(ciphertext).unwrap();
        assert_eq!(params.time_cost(), 3);
    }

    #[test]
    fn parallelism() {
        let mut plaintext: [u8; TEST_DATA.len()] = TEST_DATA.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut ciphertext = [u8::default(); TEST_DATA.len() + HEADER_SIZE + TAG_SIZE];
        let code = unsafe {
            abcrypt_encrypt_with_params(
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                32,
                3,
                4,
            )
        };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(&ciphertext[24..28], u32::to_le_bytes(4));

        let params = abcrypt::Params::new(ciphertext).unwrap();
        assert_eq!(params.parallelism(), 4);
    }
}
