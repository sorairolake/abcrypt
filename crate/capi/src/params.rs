// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use std::{ptr::NonNull, slice};

use crate::ErrorCode;

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Params {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl Params {
    /// Creates a new Argon2 parameters.
    #[must_use]
    #[inline]
    fn new() -> Option<NonNull<Self>> {
        NonNull::new(Box::into_raw(Box::default()))
    }

    /// Free a Argon2 parameters.
    #[inline]
    fn free(params: Option<NonNull<Self>>) {
        if let Some(p) = params {
            let _ = unsafe { Box::from_raw(p.as_ptr()) };
        }
    }

    /// Reads the Argon2 parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 156 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 parameters are invalid.
    /// - One of the parameters is null.
    #[must_use]
    fn read(
        ciphertext: Option<NonNull<u8>>,
        ciphertext_len: usize,
        params: Option<NonNull<Self>>,
    ) -> ErrorCode {
        let Some(ciphertext) = ciphertext else {
            return ErrorCode::Error;
        };
        let ciphertext = unsafe { slice::from_raw_parts(ciphertext.as_ptr(), ciphertext_len) };
        let p = match abcrypt::Params::new(ciphertext) {
            Ok(p) => p,
            Err(err) => {
                return err.into();
            }
        };

        let Some(params) = params else {
            return ErrorCode::Error;
        };
        unsafe {
            (*params.as_ptr()) = p.into();
        }
        ErrorCode::Ok
    }

    /// Gets memory size in KiB.
    ///
    /// Returns `0` if `params` is null.
    #[must_use]
    #[inline]
    fn m_cost(params: Option<NonNull<Self>>) -> u32 {
        params
            .map(|p| unsafe { (*p.as_ptr()).m_cost })
            .unwrap_or_default()
    }

    /// Gets number of iterations.
    ///
    /// Returns `0` if `params` is null.
    #[must_use]
    #[inline]
    fn t_cost(params: Option<NonNull<Self>>) -> u32 {
        params
            .map(|p| unsafe { (*p.as_ptr()).t_cost })
            .unwrap_or_default()
    }

    /// Gets degree of parallelism.
    ///
    /// Returns `0` if `params` is null.
    #[must_use]
    #[inline]
    fn p_cost(params: Option<NonNull<Self>>) -> u32 {
        params
            .map(|p| unsafe { (*p.as_ptr()).p_cost })
            .unwrap_or_default()
    }
}

impl Default for Params {
    fn default() -> Self {
        abcrypt::Params::default().into()
    }
}

impl From<abcrypt::Params> for Params {
    fn from(params: abcrypt::Params) -> Self {
        let (m_cost, t_cost, p_cost) = (params.m_cost(), params.t_cost(), params.p_cost());
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }
}

/// Creates a new Argon2 parameters.
#[must_use]
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_new() -> Option<NonNull<Params>> {
    Params::new()
}

/// Free a Argon2 parameters.
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_free(params: Option<NonNull<Params>>) {
    Params::free(params);
}

/// Reads the Argon2 parameters from `ciphertext`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - `ciphertext` is shorter than 156 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized abcrypt version number.
/// - The Argon2 parameters are invalid.
/// - One of the parameters is null.
#[must_use]
#[no_mangle]
pub extern "C" fn abcrypt_params_read(
    ciphertext: Option<NonNull<u8>>,
    ciphertext_len: usize,
    params: Option<NonNull<Params>>,
) -> ErrorCode {
    Params::read(ciphertext, ciphertext_len, params)
}

/// Gets memory size in KiB.
///
/// Returns `0` if `params` is null.
#[must_use]
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_m_cost(params: Option<NonNull<Params>>) -> u32 {
    Params::m_cost(params)
}

/// Gets number of iterations.
///
/// Returns `0` if `params` is null.
#[must_use]
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_t_cost(params: Option<NonNull<Params>>) -> u32 {
    Params::t_cost(params)
}

/// Gets degree of parallelism.
///
/// Returns `0` if `params` is null.
#[must_use]
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_p_cost(params: Option<NonNull<Params>>) -> u32 {
    Params::p_cost(params)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generated using `abcrypt` crate version 0.1.0.
    const TEST_DATA_ENC: &[u8] = include_bytes!("../tests/data/data.txt.abcrypt");

    #[test]
    fn success() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code = abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params);
        assert_eq!(code, ErrorCode::Ok);
        abcrypt_params_free(params);
    }

    #[test]
    fn m_cost() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code = abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params);
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(abcrypt_params_m_cost(params), 32);
        abcrypt_params_free(params);
    }

    #[test]
    fn t_cost() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code = abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params);
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(abcrypt_params_t_cost(params), 3);
        abcrypt_params_free(params);
    }

    #[test]
    fn p_cost() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code = abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params);
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(abcrypt_params_p_cost(params), 4);
        abcrypt_params_free(params);
    }
}
