// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

use argon2::{Argon2, Params};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

use crate::{
    format::{DerivedKey, Header},
    Error, Result, ARGON2_ALGORITHM, ARGON2_VERSION, HEADER_SIZE, TAG_SIZE,
};

/// Encryptor for the abcrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Encryptor<'m> {
    header: Header,
    dk: DerivedKey,
    plaintext: &'m [u8],
}

impl<'m> Encryptor<'m> {
    /// Creates a new `Encryptor`.
    ///
    /// This uses the [recommended Argon2 parameters] created by
    /// [`Params::default`].
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
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Encryptor::new(data, passphrase).unwrap();
    /// ```
    ///
    /// [recommended Argon2 parameters]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
    #[cfg(feature = "alloc")]
    pub fn new(plaintext: &'m impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self> {
        Self::with_params(plaintext, passphrase, Params::default())
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
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// ```
    pub fn with_params(
        plaintext: &'m impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        params: Params,
    ) -> Result<Self> {
        let inner = |plaintext: &'m [u8], passphrase: &[u8], params: Params| -> Result<Self> {
            let mut header = Header::new(params);

            // The derived key size is 96 bytes. The first 256 bits are for
            // XChaCha20-Poly1305 key, and the last 512 bits are for BLAKE2b-512-MAC key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            let argon2 = Argon2::new(ARGON2_ALGORITHM, ARGON2_VERSION, header.params().into());
            #[cfg(feature = "alloc")]
            argon2
                .hash_password_into(passphrase, &header.salt(), &mut dk)
                .map_err(Error::InvalidArgon2Context)?;
            #[cfg(not(feature = "alloc"))]
            {
                let mut memory_blocks = crate::MEMORY_BLOCKS;
                argon2
                    .hash_password_into_with_memory(
                        passphrase,
                        &header.salt(),
                        &mut dk,
                        &mut memory_blocks,
                    )
                    .map_err(Error::InvalidArgon2Context)?;
            }
            let dk = DerivedKey::new(dk);

            header.compute_mac(&dk.mac());

            Ok(Self {
                header,
                dk,
                plaintext,
            })
        };
        inner(plaintext.as_ref(), passphrase.as_ref(), params)
    }

    /// Encrypts the plaintext into `buf`.
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
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// let mut buf = [u8::default(); 170];
    /// cipher.encrypt(&mut buf);
    /// # assert_ne!(buf, data.as_slice());
    /// ```
    pub fn encrypt(&self, mut buf: impl AsMut<[u8]>) {
        let inner = |encryptor: &Self, buf: &mut [u8]| {
            buf[..HEADER_SIZE].copy_from_slice(&encryptor.header.as_bytes());
            buf[HEADER_SIZE..(self.out_len() - TAG_SIZE)].copy_from_slice(encryptor.plaintext);

            let cipher = XChaCha20Poly1305::new(&encryptor.dk.encrypt());
            let tag = cipher
                .encrypt_in_place_detached(
                    &encryptor.header.nonce(),
                    b"",
                    &mut buf[HEADER_SIZE..(self.out_len() - TAG_SIZE)],
                )
                .expect(
                    "the buffer should have sufficient capacity to store the resulting ciphertext",
                );
            buf[(self.out_len() - TAG_SIZE)..].copy_from_slice(&tag);
        };
        inner(self, buf.as_mut());
    }

    /// Encrypts the plaintext and into a newly allocated
    /// [`Vec`](alloc::vec::Vec).
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// let ciphertext = cipher.encrypt_to_vec();
    /// # assert_ne!(ciphertext, data);
    /// ```
    #[cfg(feature = "alloc")]
    #[must_use]
    pub fn encrypt_to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.encrypt(&mut buf);
        buf
    }

    #[allow(clippy::missing_panics_doc)]
    /// Returns the number of output bytes of the encrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Params, Encryptor};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// assert_eq!(cipher.out_len(), 170);
    /// ```
    #[must_use]
    #[inline]
    pub const fn out_len(&self) -> usize {
        assert!(self.plaintext.len() <= (usize::MAX - HEADER_SIZE - TAG_SIZE));
        HEADER_SIZE + self.plaintext.len() + TAG_SIZE
    }
}

/// Encrypts `plaintext` and into a newly allocated [`Vec`](alloc::vec::Vec).
///
/// This uses the [recommended Argon2 parameters] created by
/// [`Params::default`].
///
/// This is a convenience function for using [`Encryptor::new`] and
/// [`Encryptor::encrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if the Argon2 context is invalid.
///
/// # Examples
///
/// ```
/// let data = b"Hello, world!\n";
/// let passphrase = "passphrase";
///
/// let ciphertext = abcrypt::encrypt(data, passphrase).unwrap();
/// # assert_ne!(ciphertext, data);
/// ```
///
/// [recommended Argon2 parameters]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
#[cfg(feature = "alloc")]
pub fn encrypt(
    plaintext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
) -> Result<alloc::vec::Vec<u8>> {
    Encryptor::new(&plaintext, passphrase).map(|c| c.encrypt_to_vec())
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified [`Params`] and into a newly
/// allocated [`Vec`](alloc::vec::Vec).
///
/// This is a convenience function for using [`Encryptor::with_params`] and
/// [`Encryptor::encrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if the Argon2 context is invalid.
///
/// # Examples
///
/// ```
/// # use abcrypt::argon2::Params;
/// #
/// let data = b"Hello, world!\n";
/// let passphrase = "passphrase";
///
/// let params = Params::new(32, 3, 4, None).unwrap();
/// let ciphertext = abcrypt::encrypt_with_params(data, passphrase, params).unwrap();
/// # assert_ne!(ciphertext, data);
/// ```
#[cfg(feature = "alloc")]
pub fn encrypt_with_params(
    plaintext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
    params: Params,
) -> Result<alloc::vec::Vec<u8>> {
    Encryptor::with_params(&plaintext, passphrase, params).map(|c| c.encrypt_to_vec())
}
