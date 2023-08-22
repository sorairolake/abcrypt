// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use crate::{error::Error, format::Header};

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Debug)]
pub struct Params(argon2::Params);

impl Params {
    /// Creates a new instance of the Argon2 parameters from `data`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `data` is shorter than 156 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 parameters are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = argon2::Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, password, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    ///
    /// assert!(Params::new(ciphertext).is_ok());
    /// ```
    pub fn new(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let params = Header::parse(data.as_ref()).map(|h| h.params())?;
        Ok(Self(params))
    }

    /// Gets memory size in KiB.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = argon2::Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, password, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.m_cost(), 32);
    /// ```
    #[must_use]
    #[inline]
    pub fn m_cost(&self) -> u32 {
        self.0.m_cost()
    }

    /// Gets number of iterations.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = argon2::Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, password, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.t_cost(), 3);
    /// ```
    #[must_use]
    #[inline]
    pub fn t_cost(&self) -> u32 {
        self.0.t_cost()
    }

    /// Gets degree of parallelism.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = argon2::Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, password, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    ///
    /// let params = Params::new(ciphertext).unwrap();
    /// assert_eq!(params.p_cost(), 4);
    /// ```
    #[must_use]
    #[inline]
    pub fn p_cost(&self) -> u32 {
        self.0.p_cost()
    }
}
