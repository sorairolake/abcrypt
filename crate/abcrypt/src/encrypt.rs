// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

use alloc::vec::Vec;
use core::mem;

use argon2::{Argon2, Params};
use chacha20poly1305::{aead::Aead, KeyInit, Tag, XChaCha20Poly1305};

use crate::{
    error::Error,
    format::{DerivedKey, Header},
    ARGON2_ALGORITHM, ARGON2_VERSION,
};

/// Encryptor for the abcrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Encryptor {
    header: Header,
    dk: DerivedKey,
    data: Vec<u8>,
}

impl Encryptor {
    /// Creates a new `Encryptor`.
    ///
    /// This uses the default Argon2 parameters created by [`Params::default`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the Argon2 context is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Encryptor;
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Encryptor::new(data, passphrase).unwrap();
    /// let ciphertext = cipher.encrypt_to_vec();
    /// # assert_ne!(ciphertext, data);
    /// #
    /// # let params = abcrypt::Params::new(ciphertext).unwrap();
    /// # assert_eq!(params.m_cost(), argon2::Params::DEFAULT_M_COST);
    /// # assert_eq!(params.t_cost(), argon2::Params::DEFAULT_T_COST);
    /// # assert_eq!(params.p_cost(), argon2::Params::DEFAULT_P_COST);
    /// ```
    pub fn new(data: impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::with_params(data, passphrase, Params::default())
    }

    /// Creates a new `Encryptor` with the specified [`Params`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the Argon2 context is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// let ciphertext = cipher.encrypt_to_vec();
    /// # assert_ne!(ciphertext, data);
    /// ```
    pub fn with_params(
        data: impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        params: Params,
    ) -> Result<Self, Error> {
        let inner = |data: &[u8], passphrase: &[u8], params: Params| -> Result<Self, Error> {
            let mut header = Header::new(params);

            // The derived key size is 96 bytes. The first 256 bits are for
            // XChaCha20-Poly1305 key, and the last 512 bits are for BLAKE2b-512-MAC key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, header.params())
                .hash_password_into(passphrase, &header.salt(), &mut dk)
                .map_err(Error::InvalidArgon2Context)?;
            let dk = DerivedKey::new(dk);

            header.compute_mac(&dk.mac());

            let data = data.to_vec();
            Ok(Self { header, dk, data })
        };
        inner(data.as_ref(), passphrase.as_ref(), params)
    }

    /// Encrypts data into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if any of the following are true:
    ///
    /// - `buf` and the encrypted data have different lengths.
    /// - The buffer has insufficient capacity to store the resulting
    ///   ciphertext.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// let mut buf = [u8::default(); 169];
    /// cipher.encrypt(&mut buf);
    /// # assert_ne!(buf, data.as_slice());
    /// ```
    pub fn encrypt(self, mut buf: impl AsMut<[u8]>) {
        let inner = |encryptor: Self, buf: &mut [u8]| {
            let cipher = XChaCha20Poly1305::new(&encryptor.dk.encrypt());
            let ciphertext = cipher
                .encrypt(&encryptor.header.nonce(), encryptor.data.as_slice())
                .expect(
                    "the buffer should have sufficient capacity to store the resulting ciphertext",
                );

            buf[..Header::SIZE].copy_from_slice(&encryptor.header.as_bytes());
            buf[Header::SIZE..].copy_from_slice(&ciphertext);
        };
        inner(self, buf.as_mut());
    }

    /// Encrypts data and into a newly allocated `Vec`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// let ciphertext = cipher.encrypt_to_vec();
    /// # assert_ne!(ciphertext, data);
    /// ```
    #[must_use]
    pub fn encrypt_to_vec(self) -> Vec<u8> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.encrypt(&mut buf);
        buf
    }

    /// Returns the number of output bytes of the encrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// assert_eq!(cipher.out_len(), 169);
    /// ```
    #[must_use]
    #[inline]
    pub fn out_len(&self) -> usize {
        Header::SIZE + self.data.len() + mem::size_of::<Tag>()
    }
}
