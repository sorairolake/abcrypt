// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use crate::{format::Header, Result};

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Params {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Params {
    /// Creates a new instance of the Argon2 parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 164 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unsupported abcrypt version number.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 type is invalid.
    /// - The Argon2 version is invalid.
    /// - The Argon2 parameters are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// assert!(Params::new(ciphertext).is_ok());
    /// ```
    #[inline]
    pub fn new(ciphertext: impl AsRef<[u8]>) -> Result<Self> {
        let inner = |ciphertext: &[u8]| -> Result<Self> {
            let params = Header::parse(ciphertext).map(|h| h.params())?;
            Ok(params)
        };
        inner(ciphertext.as_ref())
    }

    /// Gets memory size in KiB.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.memory_cost(), 32);
    /// ```
    #[must_use]
    #[inline]
    pub const fn memory_cost(&self) -> u32 {
        self.memory_cost
    }

    /// Gets number of iterations.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.time_cost(), 3);
    /// ```
    #[must_use]
    #[inline]
    pub const fn time_cost(&self) -> u32 {
        self.time_cost
    }

    /// Gets degree of parallelism.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.parallelism(), 4);
    /// ```
    #[must_use]
    #[inline]
    pub const fn parallelism(&self) -> u32 {
        self.parallelism
    }
}

impl From<Params> for argon2::Params {
    #[inline]
    fn from(params: Params) -> Self {
        Self::new(
            params.memory_cost(),
            params.time_cost(),
            params.parallelism(),
            None,
        )
        .expect("`Params` should be valid as `argon2::Params`")
    }
}

impl From<argon2::Params> for Params {
    #[inline]
    fn from(params: argon2::Params) -> Self {
        let (memory_cost, time_cost, parallelism) =
            (params.m_cost(), params.t_cost(), params.p_cost());
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }
}
