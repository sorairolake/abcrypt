// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The scrypt parameters.

use crate::{error::Error, format::Header};

/// The scrypt parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
pub struct Params(scrypt::Params);

impl Params {
    /// Creates a new instance of the scrypt parameters from `data`.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - `data` is less than 128 bytes.
    /// - The magic number is not "scrypt".
    /// - The version number other than `0`.
    /// - The scrypt parameters are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = scrypt::Params::new(10, 8, 1, scrypt::Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    ///
    /// assert!(Params::new(encrypted).is_ok());
    /// ```
    pub fn new(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        let params = Header::parse(data.as_ref()).map(|h| h.params())?;
        Ok(Self(params))
    }

    /// Gets log2 of the scrypt parameter `N`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = scrypt::Params::new(10, 8, 1, scrypt::Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    ///
    /// let params = Params::new(encrypted).unwrap();
    /// assert_eq!(params.log_n(), 10);
    /// ```
    #[must_use]
    #[inline]
    pub fn log_n(&self) -> u8 {
        self.0.log_n()
    }

    /// Gets `N` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = scrypt::Params::new(10, 8, 1, scrypt::Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    ///
    /// let params = Params::new(encrypted).unwrap();
    /// assert_eq!(params.n(), 1024);
    /// ```
    #[must_use]
    #[inline]
    pub fn n(&self) -> u64 {
        1 << self.0.log_n()
    }

    /// Gets `r` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = scrypt::Params::new(10, 8, 1, scrypt::Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    ///
    /// let params = Params::new(encrypted).unwrap();
    /// assert_eq!(params.r(), 8);
    /// ```
    #[must_use]
    #[inline]
    pub fn r(&self) -> u32 {
        self.0.r()
    }

    /// Gets `p` parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{Encryptor, Params};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = scrypt::Params::new(10, 8, 1, scrypt::Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    ///
    /// let params = Params::new(encrypted).unwrap();
    /// assert_eq!(params.p(), 1);
    /// ```
    #[must_use]
    #[inline]
    pub fn p(&self) -> u32 {
        self.0.p()
    }
}
