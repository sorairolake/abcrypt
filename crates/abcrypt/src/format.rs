// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Specifications of the abcrypt encrypted data format.

use core::mem;

use argon2::Algorithm;
use blake2::{
    Blake2bMac512,
    digest::{self, Mac, Output, OutputSizeUser, typenum::Unsigned},
};
use chacha20poly1305::{
    AeadCore, Key as XChaCha20Poly1305Key, KeySizeUser, XChaCha20Poly1305, XNonce,
};
use rand::{Rng, SeedableRng, rngs::StdRng};

use crate::{Error, Params, Result, argon2_context};

/// A type alias for magic number of the abcrypt encrypted data format.
type MagicNumber = [u8; 7];

/// A type alias for salt of Argon2.
type Salt = [u8; 32];

/// A type alias for output of BLAKE2b-512-MAC.
type Blake2bMac512Output = Output<Blake2bMac512>;

/// A type alias for key of BLAKE2b-512-MAC.
type Blake2bMac512Key = digest::Key<Blake2bMac512>;

/// The number of bytes of the header.
///
/// # Examples
///
/// ```
/// assert_eq!(abcrypt::HEADER_SIZE, 148);
///
/// let ciphertext = include_bytes!("../tests/data/v1/argon2id/v0x13/data.txt.abcrypt");
/// let plaintext = include_bytes!("../tests/data/data.txt");
/// assert_eq!(
///     abcrypt::HEADER_SIZE,
///     ciphertext.len() - (plaintext.len() + abcrypt::TAG_SIZE)
/// );
/// ```
pub const HEADER_SIZE: usize = Header::SIZE;

/// The number of bytes of the MAC (authentication tag) of the ciphertext.
///
/// # Examples
///
/// ```
/// assert_eq!(abcrypt::TAG_SIZE, 16);
///
/// let ciphertext = include_bytes!("../tests/data/v1/argon2id/v0x13/data.txt.abcrypt");
/// let plaintext = include_bytes!("../tests/data/data.txt");
/// assert_eq!(
///     abcrypt::TAG_SIZE,
///     ciphertext.len() - (abcrypt::HEADER_SIZE + plaintext.len())
/// );
/// ```
pub const TAG_SIZE: usize = <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// Version of the abcrypt encrypted data format.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Version {
    /// Version 0.
    V0,

    /// Version 1.
    #[default]
    V1,
}

impl From<Version> for u8 {
    #[inline]
    fn from(version: Version) -> Self {
        version as Self
    }
}

impl TryFrom<u8> for Version {
    type Error = Error;

    #[inline]
    fn try_from(version: u8) -> Result<Self> {
        match version {
            0 => Ok(Self::V0),
            1 => Ok(Self::V1),
            v => Err(Error::UnknownVersion(v)),
        }
    }
}

/// Header of the abcrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Header {
    magic_number: MagicNumber,
    version: Version,
    argon2_type: argon2_context::Variant,
    argon2_version: argon2_context::Version,
    params: Params,
    salt: Salt,
    nonce: XNonce,
    mac: Blake2bMac512Output,
}

impl Header {
    /// Magic number of the abcrypt encrypted data format.
    ///
    /// This is the ASCII code for "abcrypt".
    const MAGIC_NUMBER: MagicNumber = *b"abcrypt";

    /// The number of bytes of the header.
    const SIZE: usize = mem::size_of::<MagicNumber>()
        + mem::size_of::<Version>()
        + mem::size_of::<argon2_context::Variant>()
        + mem::size_of::<argon2_context::Version>()
        + mem::size_of::<Params>()
        + mem::size_of::<Salt>()
        + <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE
        + <Blake2bMac512 as OutputSizeUser>::OutputSize::USIZE;

    /// Creates a new `Header`.
    pub fn new(
        argon2_type: Algorithm,
        argon2_version: argon2::Version,
        params: argon2::Params,
    ) -> Self {
        let magic_number = Self::MAGIC_NUMBER;
        let version = Version::default();
        let argon2_type = argon2_type.into();
        let argon2_version = argon2_version.into();
        let params = params.into();
        let salt = StdRng::from_entropy().r#gen();
        let nonce = XChaCha20Poly1305::generate_nonce(StdRng::from_entropy());
        let mac = Blake2bMac512Output::default();
        Self {
            magic_number,
            version,
            argon2_type,
            argon2_version,
            params,
            salt,
            nonce,
            mac,
        }
    }

    /// Parses `data` into the header.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE + TAG_SIZE {
            return Err(Error::InvalidLength);
        }

        let Some(magic_number) = Some(Self::MAGIC_NUMBER).filter(|mn| &data[..7] == mn) else {
            return Err(Error::InvalidMagicNumber);
        };
        let version = Version::try_from(data[7])?;
        if version != Version::V1 {
            return Err(Error::UnsupportedVersion(version.into()));
        }
        let argon2_type = u32::from_le_bytes(
            data[8..12]
                .try_into()
                .expect("size of the Argon2 type should be 4 bytes"),
        )
        .try_into()?;
        let argon2_version = u32::from_le_bytes(
            data[12..16]
                .try_into()
                .expect("size of the Argon2 version should be 4 bytes"),
        )
        .try_into()?;
        let memory_cost = u32::from_le_bytes(
            data[16..20]
                .try_into()
                .expect("size of `memoryCost` should be 4 bytes"),
        );
        let time_cost = u32::from_le_bytes(
            data[20..24]
                .try_into()
                .expect("size of `timeCost` should be 4 bytes"),
        );
        let parallelism = u32::from_le_bytes(
            data[24..28]
                .try_into()
                .expect("size of `parallelism` should be 4 bytes"),
        );
        let params = argon2::Params::new(memory_cost, time_cost, parallelism, None)
            .map(Params::from)
            .map_err(Error::InvalidArgon2Params)?;
        let salt = data[28..60]
            .try_into()
            .expect("size of salt should be 32 bytes");
        let nonce = *XNonce::from_slice(&data[60..84]);
        let mac = Blake2bMac512Output::default();
        Ok(Self {
            magic_number,
            version,
            argon2_type,
            argon2_version,
            params,
            salt,
            nonce,
            mac,
        })
    }

    /// Gets a BLAKE2b-512-MAC of this header.
    #[inline]
    pub fn compute_mac(&mut self, key: &Blake2bMac512Key) {
        let mut mac = Blake2bMac512::new(key);
        mac.update(&self.as_bytes()[..84]);
        self.mac.copy_from_slice(&mac.finalize().into_bytes());
    }

    /// Verifies a BLAKE2b-512-MAC stored in this header.
    pub fn verify_mac(&mut self, key: &Blake2bMac512Key, tag: &Blake2bMac512Output) -> Result<()> {
        let mut mac = Blake2bMac512::new(key);
        mac.update(&self.as_bytes()[..84]);
        mac.verify(tag)?;
        self.mac.copy_from_slice(tag);
        Ok(())
    }

    /// Converts this header to a byte array.
    pub fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut header = [u8::default(); Self::SIZE];
        header[..7].copy_from_slice(&self.magic_number);
        header[7] = self.version.into();
        header[8..12].copy_from_slice(&u32::from(self.argon2_type).to_le_bytes());
        header[12..16].copy_from_slice(&u32::from(self.argon2_version).to_le_bytes());
        header[16..20].copy_from_slice(&self.params.memory_cost().to_le_bytes());
        header[20..24].copy_from_slice(&self.params.time_cost().to_le_bytes());
        header[24..28].copy_from_slice(&self.params.parallelism().to_le_bytes());
        header[28..60].copy_from_slice(&self.salt);
        header[60..84].copy_from_slice(&self.nonce);
        header[84..].copy_from_slice(&self.mac);
        header
    }

    /// Returns the Argon2 type stored in this header.
    #[inline]
    pub const fn argon2_type(&self) -> argon2_context::Variant {
        self.argon2_type
    }

    /// Returns the Argon2 version stored in this header.
    #[inline]
    pub const fn argon2_version(&self) -> argon2_context::Version {
        self.argon2_version
    }

    /// Returns the Argon2 parameters stored in this header.
    #[inline]
    pub const fn params(&self) -> Params {
        self.params
    }

    /// Returns a salt stored in this header.
    #[inline]
    pub const fn salt(&self) -> Salt {
        self.salt
    }

    /// Returns a nonce stored in this header.
    #[inline]
    pub const fn nonce(&self) -> XNonce {
        self.nonce
    }
}

/// Derived key.
#[derive(Clone, Debug)]
pub struct DerivedKey {
    encrypt: XChaCha20Poly1305Key,
    mac: Blake2bMac512Key,
}

impl DerivedKey {
    /// The number of bytes of the derived key.
    pub const SIZE: usize = <XChaCha20Poly1305 as KeySizeUser>::KeySize::USIZE
        + <Blake2bMac512 as KeySizeUser>::KeySize::USIZE;

    /// Creates a new `DerivedKey`.
    #[inline]
    pub fn new(dk: [u8; Self::SIZE]) -> Self {
        let encrypt = *XChaCha20Poly1305Key::from_slice(&dk[..32]);
        let mac = *Blake2bMac512Key::from_slice(&dk[32..]);
        Self { encrypt, mac }
    }

    /// Returns the key for encrypted.
    #[inline]
    pub const fn encrypt(&self) -> XChaCha20Poly1305Key {
        self.encrypt
    }

    /// Returns the key for a MAC.
    #[inline]
    pub const fn mac(&self) -> Blake2bMac512Key {
        self.mac
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    #[test]
    fn header_size() {
        assert_eq!(HEADER_SIZE, 148);
        assert_eq!(HEADER_SIZE, Header::SIZE);
    }

    #[test]
    fn tag_size() {
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(TAG_SIZE, <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE);
    }

    #[test]
    fn version() {
        assert_eq!(Version::V0 as u8, 0);
        assert_eq!(Version::V1 as u8, 1);
    }

    #[test]
    fn size_of_version() {
        assert_eq!(mem::size_of::<Version>(), mem::size_of::<u8>());
    }

    #[test]
    fn clone_version() {
        assert_eq!(Version::V0.clone(), Version::V0);
        assert_eq!(Version::V1.clone(), Version::V1);
    }

    #[test]
    fn copy_version() {
        {
            let a = Version::V0;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Version::V1;
            let b = a;
            assert_eq!(a, b);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn debug_version() {
        assert_eq!(format!("{:?}", Version::V0), "V0");
        assert_eq!(format!("{:?}", Version::V1), "V1");
    }

    #[test]
    fn default_version() {
        assert_eq!(Version::default(), Version::V1);
    }

    #[test]
    fn version_equality() {
        assert_eq!(Version::V0, Version::V0);
        assert_ne!(Version::V0, Version::V1);
        assert_ne!(Version::V1, Version::V0);
        assert_eq!(Version::V1, Version::V1);
    }

    #[test]
    fn from_version_to_u8() {
        assert_eq!(u8::from(Version::V0), 0);
        assert_eq!(u8::from(Version::V1), 1);
    }

    #[test]
    fn try_from_u8_to_version() {
        assert_eq!(Version::try_from(0).unwrap(), Version::V0);
        assert_eq!(Version::try_from(1).unwrap(), Version::V1);
    }

    #[test]
    fn try_from_u8_to_version_with_invalid_version() {
        assert_eq!(Version::try_from(2).unwrap_err(), Error::UnknownVersion(2));
        assert_eq!(
            Version::try_from(u8::MAX).unwrap_err(),
            Error::UnknownVersion(u8::MAX)
        );
    }

    #[test]
    fn magic_number() {
        assert_eq!(str::from_utf8(&Header::MAGIC_NUMBER).unwrap(), "abcrypt");
    }

    #[test]
    fn derived_key_size() {
        assert_eq!(DerivedKey::SIZE, 96);
    }
}
