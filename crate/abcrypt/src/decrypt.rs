// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the abcrypt encrypted data format.

use argon2::Argon2;
use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305};

use crate::{
    format::{DerivedKey, Header},
    Error, Result, ARGON2_ALGORITHM, ARGON2_VERSION, HEADER_SIZE, TAG_SIZE,
};

/// Decryptor for the abcrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Decryptor<'c> {
    header: Header,
    dk: DerivedKey,
    ciphertext: &'c [u8],
}

impl<'c> Decryptor<'c> {
    /// Creates a new `Decryptor`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 156 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 parameters are invalid.
    /// - The Argon2 context is invalid.
    /// - The MAC (authentication tag) of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Decryptor;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// ```
    pub fn new(ciphertext: &'c impl AsRef<[u8]>, passphrase: impl AsRef<[u8]>) -> Result<Self> {
        let inner = |ciphertext: &'c [u8], passphrase: &[u8]| -> Result<Self> {
            let mut header = Header::parse(ciphertext)?;

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

            header.verify_mac(&dk.mac(), ciphertext[76..HEADER_SIZE].into())?;

            let ciphertext = &ciphertext[HEADER_SIZE..];
            Ok(Self {
                header,
                dk,
                ciphertext,
            })
        };
        inner(ciphertext.as_ref(), passphrase.as_ref())
    }

    /// Decrypts the ciphertext into `buf`.
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
    /// # use abcrypt::Decryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let mut buf = [u8::default(); 14];
    /// cipher.decrypt(&mut buf).unwrap();
    /// # assert_eq!(buf, data.as_slice());
    /// ```
    pub fn decrypt(&self, mut buf: impl AsMut<[u8]>) -> Result<()> {
        let inner = |decryptor: &Self, buf: &mut [u8]| -> Result<()> {
            let (plaintext, tag) = decryptor
                .ciphertext
                .split_at(decryptor.ciphertext.len() - TAG_SIZE);
            buf.copy_from_slice(plaintext);

            let cipher = XChaCha20Poly1305::new(&decryptor.dk.encrypt());
            cipher
                .decrypt_in_place_detached(&decryptor.header.nonce(), b"", buf, tag.into())
                .map_err(Error::InvalidMac)?;
            Ok(())
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts the ciphertext and into a newly allocated
    /// [`Vec`](alloc::vec::Vec).
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if the MAC (authentication tag) of the ciphertext is
    /// invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Decryptor;
    /// #
    /// let data = b"Hello, world!\n";
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// let plaintext = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(plaintext, data);
    /// ```
    #[cfg(feature = "alloc")]
    pub fn decrypt_to_vec(&self) -> Result<alloc::vec::Vec<u8>> {
        let mut buf = vec![u8::default(); self.out_len()];
        self.decrypt(&mut buf)?;
        Ok(buf)
    }

    /// Returns the number of output bytes of the decrypted data.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Decryptor;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
    /// let passphrase = "passphrase";
    ///
    /// let cipher = Decryptor::new(&ciphertext, passphrase).unwrap();
    /// assert_eq!(cipher.out_len(), 14);
    /// ```
    #[must_use]
    #[inline]
    pub const fn out_len(&self) -> usize {
        self.ciphertext.len() - TAG_SIZE
    }
}

/// Decrypts `ciphertext` and into a newly allocated [`Vec`](alloc::vec::Vec).
///
/// This is a convenience function for using [`Decryptor::new`] and
/// [`Decryptor::decrypt_to_vec`].
///
/// # Errors
///
/// Returns [`Err`] if any of the following are true:
///
/// - `ciphertext` is shorter than 156 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized abcrypt version number.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the ciphertext is invalid.
///
/// # Examples
///
/// ```
/// let data = b"Hello, world!\n";
/// let ciphertext = include_bytes!("../tests/data/data.txt.abcrypt");
/// let passphrase = "passphrase";
///
/// let plaintext = abcrypt::decrypt(ciphertext, passphrase).unwrap();
/// # assert_eq!(plaintext, data);
/// ```
#[cfg(feature = "alloc")]
pub fn decrypt(
    ciphertext: impl AsRef<[u8]>,
    passphrase: impl AsRef<[u8]>,
) -> Result<alloc::vec::Vec<u8>> {
    Decryptor::new(&ciphertext, passphrase).and_then(|c| c.decrypt_to_vec())
}
