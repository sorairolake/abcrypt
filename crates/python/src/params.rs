// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use pyo3::{pyclass, pymethods, PyResult};

use crate::error::Error;

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[pyclass]
pub struct Params(abcrypt::Params);

#[pymethods]
impl Params {
    /// Creates a new instance of the Argon2 parameters from `ciphertext`.
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
    #[inline]
    #[new]
    pub fn new(ciphertext: &[u8]) -> PyResult<Self> {
        let params = abcrypt::Params::new(ciphertext)
            .map(Self)
            .map_err(Error::from)?;
        Ok(params)
    }

    /// Gets memory size in KiB.
    #[must_use]
    #[inline]
    #[getter]
    pub const fn memory_cost(&self) -> u32 {
        self.0.memory_cost()
    }

    /// Gets number of iterations.
    #[must_use]
    #[inline]
    #[getter]
    pub const fn time_cost(&self) -> u32 {
        self.0.time_cost()
    }

    /// Gets degree of parallelism.
    #[must_use]
    #[inline]
    #[getter]
    pub const fn parallelism(&self) -> u32 {
        self.0.parallelism()
    }
}
