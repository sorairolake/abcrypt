// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

use crate::{
    AAD, Error, HEADER_SIZE, Result, TAG_SIZE,
    format::{DerivedKey, Header},
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
    /// This uses the recommended Argon2 parameters according to the [OWASP
    /// Password Storage Cheat Sheet] created by [`Params::default`]. This also
    /// uses the Argon2 type created by [`Algorithm::default`] and the Argon2
    /// version created by [`Version::default`].
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
    /// [OWASP Password Storage Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
    #[cfg(feature = "alloc")]
    #[inline]
    pub fn new(plaintext: &'m impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self> {
        Self::with_params(plaintext, passphrase, Params::default())
    }

    /// Creates a new `Encryptor` with the specified [`Params`].
    ///
    /// This uses the Argon2 type created by [`Algorithm::default`] and the
    /// Argon2 version created by [`Version::default`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the Argon2 context is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, argon2::Params};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// ```
    #[inline]
    pub fn with_params(
        plaintext: &'m impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        params: Params,
    ) -> Result<Self> {
        Self::with_context(
            plaintext,
            passphrase,
            Algorithm::default(),
            Version::default(),
            params,
        )
    }

    /// Creates a new `Encryptor` with the specified [`Algorithm`], [`Version`]
    /// and [`Params`].
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the Argon2 context is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{
    /// #     Encryptor,
    /// #     argon2::{Algorithm, Params, Version},
    /// # };
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher =
    ///     Encryptor::with_context(data, passphrase, Algorithm::Argon2i, Version::V0x10, params)
    ///         .unwrap();
    /// ```
    pub fn with_context(
        plaintext: &'m impl AsRef<[u8]>,
        passphrase: impl AsRef<[u8]>,
        argon2_type: Algorithm,
        argon2_version: Version,
        params: Params,
    ) -> Result<Self> {
        let inner = |plaintext: &'m [u8],
                     passphrase: &[u8],
                     argon2_type: Algorithm,
                     argon2_version: Version,
                     params: Params|
         -> Result<Self> {
            let mut header = Header::new(argon2_type, argon2_version, params);

            // The derived key size is 96 bytes. The first 256 bits are for
            // XChaCha20-Poly1305 key, and the last 512 bits are for BLAKE2b-512-MAC key.
            let mut dk = [u8::default(); DerivedKey::SIZE];
            let argon2 = Argon2::new(
                header.argon2_type().into(),
                header.argon2_version().into(),
                header.params().into(),
            );
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
        inner(
            plaintext.as_ref(),
            passphrase.as_ref(),
            argon2_type,
            argon2_version,
            params,
        )
    }

    /// Encrypts the plaintext into `buf`.
    ///
    /// # Panics
    ///
    /// Panics if any of the following are true:
    ///
    /// - `buf` and the encrypted data have different lengths.
    /// - The end of the keystream will be reached with the given data length.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, argon2::Params};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// let mut buf = [u8::default(); 178];
    /// cipher.encrypt(&mut buf);
    /// # assert_ne!(buf.as_slice(), data);
    /// ```
    pub fn encrypt(&self, buf: &mut (impl AsMut<[u8]> + ?Sized)) {
        let inner = |encryptor: &Self, buf: &mut [u8]| {
            buf[..HEADER_SIZE].copy_from_slice(&encryptor.header.as_bytes());
            let payload = &mut buf[HEADER_SIZE..(self.out_len() - TAG_SIZE)];
            payload.copy_from_slice(encryptor.plaintext);

            let cipher = XChaCha20Poly1305::new(&encryptor.dk.encrypt());
            let tag = cipher
                .encrypt_in_place_detached(&encryptor.header.nonce(), AAD, payload)
                .expect("data too long");
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
    /// # use abcrypt::{Encryptor, argon2::Params};
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
    #[inline]
    pub fn encrypt_to_vec(&self) -> alloc::vec::Vec<u8> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.encrypt(&mut buf);
        buf
    }

    /// Returns the number of output bytes of the encrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{Encryptor, argon2::Params};
    /// #
    /// let data = b"Hello, world!\n";
    /// let passphrase = "passphrase";
    ///
    /// let params = Params::new(32, 3, 4, None).unwrap();
    /// let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
    /// assert_eq!(cipher.out_len(), 178);
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
/// This uses the recommended Argon2 parameters according to the [OWASP Password
/// Storage Cheat Sheet] created by [`Params::default`]. This also uses the
/// Argon2 type created by [`Algorithm::default`] and the Argon2 version created
/// by [`Version::default`].
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
/// [OWASP Password Storage Cheat Sheet]: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
#[cfg(feature = "alloc")]
#[inline]
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
/// This uses the Argon2 type created by [`Algorithm::default`] and the Argon2
/// version created by [`Version::default`].
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
#[inline]
pub fn encrypt_with_params(
    plaintext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
    params: Params,
) -> Result<alloc::vec::Vec<u8>> {
    Encryptor::with_params(&plaintext, passphrase, params).map(|c| c.encrypt_to_vec())
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified [`Algorithm`], [`Version`] and
/// [`Params`] and into a newly allocated [`Vec`](alloc::vec::Vec).
///
/// This is a convenience function for using [`Encryptor::with_context`] and
/// [`Encryptor::encrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if the Argon2 context is invalid.
///
/// # Examples
///
/// ```
/// # use abcrypt::argon2::{Algorithm, Params, Version};
/// #
/// let data = b"Hello, world!\n";
/// let passphrase = "passphrase";
///
/// let params = Params::new(32, 3, 4, None).unwrap();
/// let ciphertext =
///     abcrypt::encrypt_with_context(data, passphrase, Algorithm::Argon2i, Version::V0x10, params)
///         .unwrap();
/// # assert_ne!(ciphertext, data);
/// ```
#[cfg(feature = "alloc")]
#[inline]
pub fn encrypt_with_context(
    plaintext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
    argon2_type: Algorithm,
    argon2_version: Version,
    params: Params,
) -> Result<alloc::vec::Vec<u8>> {
    Encryptor::with_context(&plaintext, passphrase, argon2_type, argon2_version, params)
        .map(|c| c.encrypt_to_vec())
}
