// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt-py` crate is the Python bindings for the `abcrypt` crate.

#![doc(html_root_url = "https://docs.rs/abcrypt-py/0.1.4/")]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]
#![allow(clippy::redundant_pub_crate)]

mod error;
mod params;

use std::borrow::Cow;

use abcrypt::argon2;
use pyo3::{
    exceptions::PyValueError, pyclass, pyfunction, pymethods, pymodule, types::PyModule,
    wrap_pyfunction, Bound, PyResult,
};

pub use crate::params::Params;

use crate::error::Error;

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
/// This uses the recommended Argon2 parameters.
///
/// # Errors
///
/// Returns an error if the Argon2 context is invalid.
#[pyfunction]
pub fn encrypt<'a>(plaintext: &[u8], passphrase: &[u8]) -> PyResult<Cow<'a, [u8]>> {
    let ciphertext = abcrypt::encrypt(plaintext, passphrase).map_err(Error::from)?;
    Ok(ciphertext.into())
}

/// Encrypts `plaintext` with the specified Argon2 parameters and into a newly
/// allocated `bytes`.
///
/// # Errors
///
/// Returns an error if the Argon2 context is invalid.
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

/// Decrypts `ciphertext` and into a newly allocated `bytes`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - `ciphertext` is shorter than 156 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized abcrypt version number.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the ciphertext is invalid.
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
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_class::<Params>()?;
    m.add_class::<Format>()?;
    Ok(())
}
