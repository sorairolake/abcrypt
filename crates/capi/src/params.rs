// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use std::{ptr::NonNull, slice};

use abcrypt::argon2;

use crate::ErrorCode;

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct Params {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Params {
    /// Creates a new Argon2 parameters.
    #[must_use]
    #[inline]
    fn new() -> Option<NonNull<Self>> {
        NonNull::new(Box::into_raw(Box::default()))
    }

    /// Frees a Argon2 parameters.
    ///
    /// # Safety
    ///
    /// This must not violate the safety conditions of `Box::from_raw`.
    #[inline]
    unsafe fn free(params: Option<NonNull<Self>>) {
        if let Some(p) = params {
            // SAFETY: just checked that `p` is not a null pointer.
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
    ///
    /// # Safety
    ///
    /// Behavior is undefined if `ciphertext` and `ciphertext_len` violates the
    /// safety conditions of `slice::from_raw_parts`.
    #[must_use]
    unsafe fn read(
        ciphertext: Option<NonNull<u8>>,
        ciphertext_len: usize,
        params: Option<NonNull<Self>>,
    ) -> ErrorCode {
        let Some(ciphertext) = ciphertext else {
            return ErrorCode::Error;
        };
        // SAFETY: just checked that `ciphertext` is not a null pointer.
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
        // SAFETY: just checked that `params` is not a null pointer.
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
    fn memory_cost(params: Option<NonNull<Self>>) -> u32 {
        // SAFETY: just checked that `params` is not a null pointer.
        params
            .map(|p| unsafe { (*p.as_ptr()).memory_cost })
            .unwrap_or_default()
    }

    /// Gets number of iterations.
    ///
    /// Returns `0` if `params` is null.
    #[must_use]
    #[inline]
    fn time_cost(params: Option<NonNull<Self>>) -> u32 {
        // SAFETY: just checked that `params` is not a null pointer.
        params
            .map(|p| unsafe { (*p.as_ptr()).time_cost })
            .unwrap_or_default()
    }

    /// Gets degree of parallelism.
    ///
    /// Returns `0` if `params` is null.
    #[must_use]
    #[inline]
    fn parallelism(params: Option<NonNull<Self>>) -> u32 {
        // SAFETY: just checked that `params` is not a null pointer.
        params
            .map(|p| unsafe { (*p.as_ptr()).parallelism })
            .unwrap_or_default()
    }
}

impl Default for Params {
    fn default() -> Self {
        let (memory_cost, time_cost, parallelism) = (
            argon2::Params::DEFAULT_M_COST,
            argon2::Params::DEFAULT_T_COST,
            argon2::Params::DEFAULT_P_COST,
        );
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }
}

impl From<abcrypt::Params> for Params {
    fn from(params: abcrypt::Params) -> Self {
        let (memory_cost, time_cost, parallelism) = (
            params.memory_cost(),
            params.time_cost(),
            params.parallelism(),
        );
        Self {
            memory_cost,
            time_cost,
            parallelism,
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

/// Frees a Argon2 parameters.
///
/// # Safety
///
/// This must not violate the safety conditions of `Box::from_raw`.
#[no_mangle]
#[inline]
pub unsafe extern "C" fn abcrypt_params_free(params: Option<NonNull<Params>>) {
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
///
/// # Safety
///
/// Behavior is undefined if `ciphertext` and `ciphertext_len` violates the
/// safety conditions of `slice::from_raw_parts`.
#[must_use]
#[no_mangle]
pub unsafe extern "C" fn abcrypt_params_read(
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
pub extern "C" fn abcrypt_params_memory_cost(params: Option<NonNull<Params>>) -> u32 {
    Params::memory_cost(params)
}

/// Gets number of iterations.
///
/// Returns `0` if `params` is null.
#[must_use]
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_time_cost(params: Option<NonNull<Params>>) -> u32 {
    Params::time_cost(params)
}

/// Gets degree of parallelism.
///
/// Returns `0` if `params` is null.
#[must_use]
#[no_mangle]
#[inline]
pub extern "C" fn abcrypt_params_parallelism(params: Option<NonNull<Params>>) -> u32 {
    Params::parallelism(params)
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
        let code =
            unsafe { abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params) };
        assert_eq!(code, ErrorCode::Ok);
        unsafe { abcrypt_params_free(params) };
    }

    #[test]
    fn memory_cost() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code =
            unsafe { abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params) };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(abcrypt_params_memory_cost(params), 32);
        unsafe { abcrypt_params_free(params) };
    }

    #[test]
    fn time_cost() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code =
            unsafe { abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params) };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(abcrypt_params_time_cost(params), 3);
        unsafe { abcrypt_params_free(params) };
    }

    #[test]
    fn parallelism() {
        let mut data: [u8; TEST_DATA_ENC.len()] = TEST_DATA_ENC.try_into().unwrap();
        let params = abcrypt_params_new();
        let code =
            unsafe { abcrypt_params_read(NonNull::new(data.as_mut_ptr()), data.len(), params) };
        assert_eq!(code, ErrorCode::Ok);
        assert_eq!(abcrypt_params_parallelism(params), 4);
        unsafe { abcrypt_params_free(params) };
    }
}
