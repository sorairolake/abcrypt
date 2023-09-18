// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Specifications of the abcrypt encrypted data format.

use core::mem;

use blake2::{
    digest::{self, typenum::Unsigned, Mac, Output, OutputSizeUser},
    Blake2bMac512,
};
use chacha20poly1305::{
    AeadCore, Key as XChaCha20Poly1305Key, KeySizeUser, XChaCha20Poly1305, XNonce,
};
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{Error, Params, Result};

/// A type alias for magic number of the abcrypt encrypted data format.
type MagicNumber = [u8; 7];

/// A type alias for salt of Argon2.
type Salt = [u8; 32];

/// A type alias for output of BLAKE2b-512-MAC.
type Blake2bMac512Output = Output<Blake2bMac512>;

/// A type alias for key of BLAKE2b-512-MAC.
type Blake2bMac512Key = digest::Key<Blake2bMac512>;

/// Version of the abcrypt encrypted data format.
#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Version {
    /// Version 0.
    V0,
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as Self
    }
}

/// Header of the abcrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Header {
    magic_number: MagicNumber,
    version: Version,
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
    pub const SIZE: usize = mem::size_of::<MagicNumber>()
        + mem::size_of::<Version>()
        + mem::size_of::<Params>()
        + mem::size_of::<Salt>()
        + <XChaCha20Poly1305 as AeadCore>::NonceSize::USIZE
        + <Blake2bMac512 as OutputSizeUser>::OutputSize::USIZE;

    /// Creates a new `Header`.
    pub fn new(params: argon2::Params) -> Self {
        let magic_number = Self::MAGIC_NUMBER;
        let version = Version::V0;
        let params = params.into();
        let salt = StdRng::from_entropy().gen();
        let nonce = XChaCha20Poly1305::generate_nonce(&mut StdRng::from_entropy());
        let mac = Blake2bMac512Output::default();
        Self {
            magic_number,
            version,
            params,
            salt,
            nonce,
            mac,
        }
    }

    /// Parses `data` into the header.
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < Self::SIZE + <XChaCha20Poly1305 as AeadCore>::TagSize::USIZE {
            return Err(Error::InvalidLength);
        }

        let magic_number = if data[..7] == Self::MAGIC_NUMBER {
            Ok(Self::MAGIC_NUMBER)
        } else {
            Err(Error::InvalidMagicNumber)
        }?;
        let version = if data[7] == Version::V0.into() {
            Ok(Version::V0)
        } else {
            Err(Error::UnknownVersion(data[7]))
        }?;
        let m_cost = u32::from_le_bytes(
            data[8..12]
                .try_into()
                .expect("size of `m_cost` should be 4 bytes"),
        );
        let t_cost = u32::from_le_bytes(
            data[12..16]
                .try_into()
                .expect("size of `t_cost` should be 4 bytes"),
        );
        let p_cost = u32::from_le_bytes(
            data[16..20]
                .try_into()
                .expect("size of `p_cost` should be 4 bytes"),
        );
        let params = argon2::Params::new(m_cost, t_cost, p_cost, None)
            .map(Params::from)
            .map_err(Error::InvalidArgon2Params)?;
        let salt = data[20..52]
            .try_into()
            .expect("size of salt should be 32 bytes");
        let nonce = XNonce::clone_from_slice(&data[52..76]);
        let mac = Blake2bMac512Output::default();
        Ok(Self {
            magic_number,
            version,
            params,
            salt,
            nonce,
            mac,
        })
    }

    /// Gets a BLAKE2b-512-MAC of this header.
    pub fn compute_mac(&mut self, key: &Blake2bMac512Key) {
        let mut mac = Blake2bMac512::new(key);
        mac.update(&self.as_bytes()[..76]);
        self.mac.copy_from_slice(&mac.finalize().into_bytes());
    }

    /// Verifies a BLAKE2b-512-MAC stored in this header.
    pub fn verify_mac(&mut self, key: &Blake2bMac512Key, tag: &Blake2bMac512Output) -> Result<()> {
        let mut mac = Blake2bMac512::new(key);
        mac.update(&self.as_bytes()[..76]);
        mac.verify(tag).map_err(Error::InvalidHeaderMac)?;
        self.mac.copy_from_slice(tag);
        Ok(())
    }

    /// Converts this header to a byte array.
    pub fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut header = [u8::default(); Self::SIZE];
        header[..7].copy_from_slice(&self.magic_number);
        header[7] = self.version.into();
        header[8..12].copy_from_slice(&self.params.m_cost().to_le_bytes());
        header[12..16].copy_from_slice(&self.params.t_cost().to_le_bytes());
        header[16..20].copy_from_slice(&self.params.p_cost().to_le_bytes());
        header[20..52].copy_from_slice(&self.salt);
        header[52..76].copy_from_slice(&self.nonce);
        header[76..].copy_from_slice(&self.mac);
        header
    }

    /// Returns the Argon2 parameters stored in this header.
    pub const fn params(&self) -> Params {
        self.params
    }

    /// Returns a salt stored in this header.
    pub const fn salt(&self) -> Salt {
        self.salt
    }

    /// Returns a nonce stored in this header.
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
    pub fn new(dk: [u8; Self::SIZE]) -> Self {
        let encrypt = XChaCha20Poly1305Key::clone_from_slice(&dk[..32]);
        let mac = Blake2bMac512Key::clone_from_slice(&dk[32..]);
        Self { encrypt, mac }
    }

    /// Returns the key for encrypted.
    pub const fn encrypt(&self) -> XChaCha20Poly1305Key {
        self.encrypt
    }

    /// Returns the key for a MAC.
    pub const fn mac(&self) -> Blake2bMac512Key {
        self.mac
    }
}

#[cfg(test)]
mod tests {
    use core::str;

    use super::*;

    #[test]
    fn version() {
        assert_eq!(Version::V0 as u8, 0);
    }

    #[test]
    fn from_version_to_u8() {
        assert_eq!(u8::from(Version::V0), 0);
    }

    #[test]
    fn magic_number() {
        assert_eq!(str::from_utf8(&Header::MAGIC_NUMBER).unwrap(), "abcrypt");
    }

    #[test]
    fn header_size() {
        assert_eq!(Header::SIZE, 140);
    }

    #[test]
    fn derived_key_size() {
        assert_eq!(DerivedKey::SIZE, 96);
    }
}
