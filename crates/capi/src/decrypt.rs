// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the abcrypt encrypted data format.

use std::{ptr::NonNull, slice};

use abcrypt::Decryptor;

use crate::ErrorCode;

#[allow(clippy::module_name_repetitions)]
/// Decrypts `ciphertext` and write to `out`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - `ciphertext` is shorter than 164 bytes.
/// - The magic number is invalid.
/// - The version number is the unsupported abcrypt version number.
/// - The version number is the unrecognized abcrypt version number.
/// - The Argon2 type is invalid.
/// - The Argon2 version is invalid.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the ciphertext is invalid.
/// - One of the parameters is null.
///
/// # Safety
///
/// Behavior is undefined if any of the following violates the safety conditions
/// of `slice::from_raw_parts`:
///
/// - `ciphertext` and `ciphertext_len`.
/// - `passphrase` and `passphrase_len`.
/// - `out` and `out_len`.
#[unsafe(no_mangle)]
pub unsafe extern "C-unwind" fn abcrypt_decrypt(
    ciphertext: Option<NonNull<u8>>,
    ciphertext_len: usize,
    passphrase: Option<NonNull<u8>>,
    passphrase_len: usize,
    out: Option<NonNull<u8>>,
    out_len: usize,
) -> ErrorCode {
    let Some(ciphertext) = ciphertext else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `ciphertext` is not a null pointer.
    let ciphertext = unsafe { slice::from_raw_parts(ciphertext.as_ptr(), ciphertext_len) };
    let Some(passphrase) = passphrase else {
        return ErrorCode::Error;
    };
    // SAFETY: just checked that `passphrase` is not a null pointer.
    let passphrase = unsafe { slice::from_raw_parts(passphrase.as_ptr(), passphrase_len) };
    let cipher = match Decryptor::new(&ciphertext, passphrase) {
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
    cipher
        .decrypt(out)
        .map_or_else(ErrorCode::from, |()| ErrorCode::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HEADER_SIZE, TAG_SIZE};

    const PASSPHRASE: &str = "passphrase";
    const TEST_DATA: &[u8] = include_bytes!("../tests/data/data.txt");
    // Generated using `abcrypt` crate version 0.4.0.
    const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/v1/argon2id/v0x13/data.txt.abcrypt");

    #[test]
    fn success() {
        {
            const TEST_DATA_ENC: &[u8] =
                include_bytes!("../tests/data/v1/argon2d/v0x10/data.txt.abcrypt");
            let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        {
            const TEST_DATA_ENC: &[u8] =
                include_bytes!("../tests/data/v1/argon2d/v0x13/data.txt.abcrypt");
            let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        {
            const TEST_DATA_ENC: &[u8] =
                include_bytes!("../tests/data/v1/argon2i/v0x10/data.txt.abcrypt");
            let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        {
            const TEST_DATA_ENC: &[u8] =
                include_bytes!("../tests/data/v1/argon2i/v0x13/data.txt.abcrypt");
            let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        {
            const TEST_DATA_ENC: &[u8] =
                include_bytes!("../tests/data/v1/argon2id/v0x10/data.txt.abcrypt");
            let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        {
            let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
    }

    #[test]
    #[should_panic(
        expected = "source slice length (14) does not match destination slice length (15)"
    )]
    fn invalid_output_length() {
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut plaintext = [u8::default(); TEST_DATA.len() + 1];
        assert_ne!(plaintext, TEST_DATA);
        let _ = unsafe {
            abcrypt_decrypt(
                NonNull::new(ciphertext.as_mut_ptr()),
                ciphertext.len(),
                NonNull::new(passphrase.as_mut_ptr()),
                passphrase.len(),
                NonNull::new(plaintext.as_mut_ptr()),
                plaintext.len(),
            )
        };
    }

    #[test]
    fn incorrect_passphrase() {
        const PASSPHRASE: &str = "password";
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        assert_eq!(code, ErrorCode::InvalidHeaderMac);
    }

    #[test]
    fn invalid_input_length() {
        {
            let mut ciphertext = [u8::default(); (HEADER_SIZE + TAG_SIZE) - 1];
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
            assert_eq!(code, ErrorCode::InvalidLength);
        }

        {
            let mut ciphertext = [u8::default(); HEADER_SIZE + TAG_SIZE];
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
            assert_eq!(code, ErrorCode::InvalidMagicNumber);
        }
    }

    #[test]
    fn invalid_magic_number() {
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        ciphertext[0] = u32::from('b').try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        assert_eq!(code, ErrorCode::InvalidMagicNumber);
    }

    #[test]
    fn unsupported_version() {
        const TEST_DATA_V0: &[u8] = include_bytes!("../tests/data/v0/data.txt.abcrypt");
        let mut ciphertext: [u8; TEST_DATA_V0.len()] = TEST_DATA_V0.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        assert_eq!(code, ErrorCode::UnsupportedVersion);
    }

    #[test]
    fn unknown_version() {
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        ciphertext[7] = 2;
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
        assert_eq!(code, ErrorCode::UnknownVersion);
    }

    #[test]
    fn invalid_params() {
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();

        {
            ciphertext[16..20].copy_from_slice(&u32::to_le_bytes(7));
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
            assert_eq!(code, ErrorCode::InvalidArgon2Params);
        }

        {
            ciphertext[20..24].copy_from_slice(&u32::to_le_bytes(0));
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
            assert_eq!(code, ErrorCode::InvalidArgon2Params);
        }

        {
            ciphertext[24..28].copy_from_slice(&u32::pow(2, 24).to_le_bytes());
            let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
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
            assert_eq!(code, ErrorCode::InvalidArgon2Params);
        }
    }

    #[test]
    fn invalid_header_mac() {
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut plaintext = [u8::default(); TEST_DATA.len()];
        assert_ne!(plaintext, TEST_DATA);
        let mut header_mac: [u8; 64] = ciphertext[84..148].try_into().unwrap();
        header_mac.reverse();
        ciphertext[84..148].copy_from_slice(&header_mac);
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
        assert_eq!(code, ErrorCode::InvalidHeaderMac);
    }

    #[test]
    fn invalid_mac() {
        let mut ciphertext: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let mut passphrase: [u8; PASSPHRASE.len()] = PASSPHRASE.as_bytes().try_into().unwrap();
        let mut plaintext = [u8::default(); TEST_DATA.len()];
        assert_ne!(plaintext, TEST_DATA);
        let start_mac = ciphertext.len() - TAG_SIZE;
        let mut mac: [u8; TAG_SIZE] = ciphertext[start_mac..].try_into().unwrap();
        mac.reverse();
        ciphertext[start_mac..].copy_from_slice(&mac);
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
        assert_eq!(code, ErrorCode::InvalidMac);
    }
}
