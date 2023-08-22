// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the scrypt encrypted data format.

use alloc::vec::Vec;

use aes::{
    cipher::{generic_array::GenericArray, KeyIvInit, StreamCipher},
    Aes256,
};
use ctr::Ctr128BE;

use crate::{
    error::Error,
    format::{self, DerivedKey, Header, HeaderMac},
};

/// Decryptor for the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Decryptor {
    header: Header,
    dk: DerivedKey,
    data: Vec<u8>,
    header_mac: HeaderMac,
}

impl Decryptor {
    #[allow(clippy::missing_panics_doc)]
    /// Creates a new `Decryptor`.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - `data` is less than 128 bytes.
    /// - The magic number is not "scrypt".
    /// - The version number other than `0`.
    /// - The scrypt parameters are invalid.
    /// - SHA-256 checksum of the header mismatch.
    /// - HMAC-SHA-256 of the header is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// let decrypted = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(decrypted, data);
    /// ```
    pub fn new(data: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Result<Self, Error> {
        let inner = |data: &[u8], password: &[u8]| -> Result<Self, Error> {
            let mut header = Header::parse(data)?;

            header.verify_checksum(&data[48..64])?;

            // The derived key size is 64 bytes. The first 256 bits are for AES-256-CTR key,
            // and the last 256 bits are for HMAC-SHA-256 key.
            let mut dk = [u8::default(); 64];
            scrypt::scrypt(password, &header.salt(), &header.params(), &mut dk)
                .expect("derived key size should be 64 bytes");
            let dk = DerivedKey::new(dk);

            header.verify_mac(&dk, &data[64..Header::SIZE])?;

            let (data, header_mac) =
                data[Header::SIZE..].split_at(data.len() - Header::SIZE - HeaderMac::SIZE);
            let data = data.to_vec();
            let header_mac = HeaderMac::new(
                header_mac
                    .try_into()
                    .expect("output size of HMAC-SHA-256 should be 256 bits"),
            );
            Ok(Self {
                header,
                dk,
                data,
                header_mac,
            })
        };
        inner(data.as_ref(), password.as_ref())
    }

    /// Decrypts data into `buf`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 at EOF is invalid.
    ///
    /// # Panics
    ///
    /// Panics if `buf` and the decrypted data have different lengths.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// let mut buf = [u8::default(); 13];
    /// cipher.decrypt(&mut buf).unwrap();
    /// # assert_eq!(buf, data.as_slice());
    /// ```
    pub fn decrypt(self, mut buf: impl AsMut<[u8]>) -> Result<(), Error> {
        let inner = |decryptor: Self, buf: &mut [u8]| -> Result<(), Error> {
            type Aes256Ctr128BE = Ctr128BE<Aes256>;

            let input = [decryptor.header.as_bytes().as_slice(), &decryptor.data].concat();

            let mut cipher =
                Aes256Ctr128BE::new(&decryptor.dk.encrypt().into(), &GenericArray::default());
            let mut data = decryptor.data;
            cipher.apply_keystream(&mut data);

            format::verify_mac(
                &decryptor.dk.mac(),
                &input,
                &decryptor.header_mac.as_bytes(),
            )
            .map_err(Error::InvalidMac)?;

            buf.copy_from_slice(&data);
            Ok(())
        };
        inner(self, buf.as_mut())
    }

    /// Decrypts data and into a newly allocated `Vec`.
    ///
    /// # Errors
    ///
    /// Returns `Err` if HMAC-SHA-256 at EOF is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// let decrypted = cipher.decrypt_to_vec().unwrap();
    /// # assert_eq!(decrypted, data);
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
    /// # use scryptenc::{scrypt::Params, Decryptor, Encryptor};
    /// #
    /// let data = b"Hello, world!";
    /// let password = "password";
    ///
    /// let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
    /// let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
    /// # assert_ne!(encrypted, data);
    ///
    /// let cipher = Decryptor::new(encrypted, password).unwrap();
    /// assert_eq!(cipher.out_len(), 13);
    /// ```
    #[must_use]
    #[inline]
    pub fn out_len(&self) -> usize {
        self.data.len()
    }
}
