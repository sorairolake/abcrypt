// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use crate::{format::Header, Result};

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Debug)]
pub struct Params(argon2::Params);

impl Params {
    /// Creates a new instance of the Argon2 parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 156 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 parameters are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    ///
    /// assert!(Params::new(ciphertext).is_ok());
    /// ```
    pub fn new(ciphertext: impl AsRef<[u8]>) -> Result<Self> {
        let params = Header::parse(ciphertext.as_ref()).map(|h| h.params())?;
        Ok(Self(params))
    }

    /// Gets memory size in KiB.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.m_cost(), 32);
    /// ```
    #[must_use]
    #[inline]
    pub const fn m_cost(&self) -> u32 {
        self.0.m_cost()
    }

    /// Gets number of iterations.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.t_cost(), 3);
    /// ```
    #[must_use]
    #[inline]
    pub const fn t_cost(&self) -> u32 {
        self.0.t_cost()
    }

    /// Gets degree of parallelism.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Params;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.p_cost(), 4);
    /// ```
    #[must_use]
    #[inline]
    pub const fn p_cost(&self) -> u32 {
        self.0.p_cost()
    }
}
