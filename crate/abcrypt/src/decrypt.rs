// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the abcrypt encrypted data format.

use alloc::vec::Vec;

use argon2::Argon2;
use chacha20poly1305::{
    aead::generic_array::typenum::Unsigned, aead::Aead, AeadCore, KeyInit, XChaCha20Poly1305,
};

use crate::{
    error::Error,
    format::{DerivedKey, Header},
    ARGON2_ALGORITHM, ARGON2_VERSION,
};

/// Decryptor for the abcrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Decryptor {
    header: Header,
    dk: DerivedKey,
    ciphertext: Vec<u8>,
}

impl Decryptor {
    /// Creates a new `Decryptor`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `data` is shorter than 156 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 parameters are invalid.
    /// - The Argon2 context is invalid.
    /// - The MAC (authentication tag) of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, passphrase, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    /// # assert_ne!(ciphertext, data);
    ///
    /// let cipher = Decryptor::new(ciphertext, passphrase).unwrap();
    /// let plaintext = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(plaintext, data);
    /// ```
    pub fn new(data: impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self, Error> {
        let inner = |data: &[u8], passphrase: &[u8]| -> Result<Self, Error> {
            let mut header = Header::parse(data)?;

            // The derived key size is 96 bytes. The first 256 bits are for
            // XChaCha20-Poly1305 key, and the last 512 bits are for BLAKE2b-512-MAC key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, header.params())
                .hash_password_into(passphrase, &header.salt(), &mut dk)
                .map_err(Error::InvalidArgon2Context)?;
            let dk = DerivedKey::new(dk);

            header.verify_mac(&dk.mac(), &data[76..Header::SIZE])?;

            let ciphertext = data[Header::SIZE..].to_vec();
            Ok(Self {
                header,
                dk,
                ciphertext,
            })
        };
        inner(data.as_ref(), passphrase.as_ref())
    }

    /// Decrypts data into `buf`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the MAC (authentication tag) of the ciphertext is
    /// invalid.
    ///
    /// # Panics
    ///
    /// Panics if `buf` and the decrypted data have different lengths.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, passphrase, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    /// # assert_ne!(ciphertext, data);
    ///
    /// let cipher = Decryptor::new(ciphertext, passphrase).unwrap();
    /// let mut buf = [u8::default(); 13];
    /// cipher.decrypt(&mut buf).unwrap();
    /// # assert_eq!(buf, data.as_slice());
    /// ```
    pub fn decrypt(self, mut buf: impl AsMut<[u8]>) -> Result<(), Error> {
        let inner = |decryptor: Self, buf: &mut [u8]| -> Result<(), Error> {
            let cipher = XChaCha20Poly1305::new(&decryptor.dk.encrypt());
            let plaintext = cipher
                .decrypt(&decryptor.header.nonce(), decryptor.ciphertext.as_slice())
                .map_err(Error::InvalidMac)?;

            buf.copy_from_slice(&plaintext);
            Ok(())
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts data and into a newly allocated `Vec`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the MAC (authentication tag) of the ciphertext is
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, passphrase, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    /// # assert_ne!(ciphertext, data);
    ///
    /// let cipher = Decryptor::new(ciphertext, passphrase).unwrap();
    /// let plaintext = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(plaintext, data);
    /// ```
    pub fn decrypt_to_vec(self) -> Result<Vec<u8>, Error> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.decrypt(&mut buf)?;
        Ok(buf)
    }

    /// Returns the number of output bytes of the decrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let ciphertext = Encryptor::with_params(data, passphrase, params)
    ///     .map(Encryptor::encrypt_to_vec)
    ///     .unwrap();
    /// # assert_ne!(ciphertext, data);
    ///
    /// let cipher = Decryptor::new(ciphertext, passphrase).unwrap();
    /// assert_eq!(cipher.out_len(), 13);
    /// ```
    #[must_use]
    #[inline]
    pub fn out_len(&self) -> usize {
        self.ciphertext.len() - <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE
    }
}
