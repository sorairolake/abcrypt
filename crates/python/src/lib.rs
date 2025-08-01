// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt-py` crate is the Python bindings for the `abcrypt` crate.

#![doc(html_root_url = "https://docs.rs/abcrypt-py/0.3.0/")]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_docs)]
// Lint levels of Clippy.
#![allow(clippy::redundant_pub_crate)]

mod error;
mod params;

use std::borrow::Cow;

use abcrypt::argon2::{self, Algorithm, Version};
use pyo3::{
    Bound, PyResult, exceptions::PyValueError, prelude::PyModuleMethods, pyclass, pyfunction,
    pymethods, pymodule, types::PyModule, wrap_pyfunction,
};

use crate::error::Error;
pub use crate::params::Params;

/// Specifications of the abcrypt encrypted data format.
#[derive(Clone, Copy, Debug)]
#[pyclass]
pub struct Format;

#[pymethods]
impl Format {
    /// The number of bytes of the header.
    #[classattr]
    pub const HEADER_SIZE: usize = abcrypt::HEADER_SIZE;

    /// The number of bytes of the MAC (authentication tag) of the ciphertext.
    #[classattr]
    pub const TAG_SIZE: usize = abcrypt::TAG_SIZE;
}

/// Encrypts `plaintext` and into a newly allocated `bytes`.
///
/// This uses the recommended Argon2 parameters according to the OWASP Password
/// Storage Cheat Sheet. This also uses Argon2id as the Argon2 type and version
/// 0x13 as the Argon2 version.
///
/// # Errors
///
/// Returns an error if the Argon2 context is invalid.
#[inline]
#[pyfunction]
pub fn encrypt<'a>(plaintext: &[u8], passphrase: &[u8]) -> PyResult<Cow<'a, [u8]>> {
    let ciphertext = abcrypt::encrypt(plaintext, passphrase).map_err(Error::from)?;
    Ok(ciphertext.into())
}

/// Encrypts `plaintext` with the specified Argon2 parameters and into a newly
/// allocated `bytes`.
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
#[inline]
#[pyfunction]
pub fn encrypt_with_params<'a>(
    plaintext: &[u8],
    passphrase: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> PyResult<Cow<'a, [u8]>> {
    let params = argon2::Params::new(memory_cost, time_cost, parallelism, None)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ciphertext =
        abcrypt::encrypt_with_params(plaintext, passphrase, params).map_err(Error::from)?;
    Ok(ciphertext.into())
}

/// Encrypts `plaintext` with the specified Argon2 type, Argon2 version and
/// Argon2 parameters and into a newly allocated `bytes`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - The Argon2 type is invalid.
/// - The Argon2 version is invalid.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
#[inline]
#[pyfunction]
pub fn encrypt_with_context<'a>(
    plaintext: &[u8],
    passphrase: &[u8],
    argon2_type: u32,
    argon2_version: u32,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> PyResult<Cow<'a, [u8]>> {
    let argon2_type = match argon2_type {
        0 => Ok(Algorithm::Argon2d),
        1 => Ok(Algorithm::Argon2i),
        2 => Ok(Algorithm::Argon2id),
        t => Err(abcrypt::Error::InvalidArgon2Type(t)),
    }
    .map_err(Error::from)?;
    let argon2_version =
        Version::try_from(argon2_version).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let params = argon2::Params::new(memory_cost, time_cost, parallelism, None)
        .map_err(|e| PyValueError::new_err(e.to_string()))?;
    let ciphertext =
        abcrypt::encrypt_with_context(plaintext, passphrase, argon2_type, argon2_version, params)
            .map_err(Error::from)?;
    Ok(ciphertext.into())
}

/// Decrypts `ciphertext` and into a newly allocated `bytes`.
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
#[inline]
#[pyfunction]
pub fn decrypt<'a>(ciphertext: &[u8], passphrase: &[u8]) -> PyResult<Cow<'a, [u8]>> {
    let plaintext = abcrypt::decrypt(ciphertext, passphrase).map_err(Error::from)?;
    Ok(plaintext.into())
}

/// A Python module implemented in Rust.
#[pymodule]
fn abcrypt_py(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_with_params, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt_with_context, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_class::<Params>()?;
    m.add_class::<Format>()?;
    Ok(())
}
