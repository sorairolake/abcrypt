// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Specifications of the scrypt encrypted data format.

use core::mem;

use hmac::{digest::MacError, Hmac, Mac};
use rand::{rngs::StdRng, Rng, SeedableRng};
use sha2::{Digest, Sha256};

use crate::error::Error;

/// Version of the scrypt data file.
#[derive(Clone, Copy, Debug)]
pub enum Version {
    /// Version 0.
    V0,
}

impl From<Version> for u8 {
    fn from(version: Version) -> Self {
        version as Self
    }
}

/// Header of the scrypt encrypted data format.
#[derive(Clone, Debug)]
pub struct Header {
    magic_number: [u8; 6],
    version: Version,
    params: scrypt::Params,
    salt: [u8; 32],
    checksum: [u8; 16],
    mac: [u8; HeaderMac::SIZE],
}

impl Header {
    /// Magic number of the scrypt encrypted data format.
    ///
    /// This is the ASCII code for "scrypt".
    const MAGIC_NUMBER: [u8; 6] = *b"scrypt";

    /// The number of bytes of the header.
    pub const SIZE: usize = 96;

    /// Creates a new `Header`.
    pub fn new(params: scrypt::Params) -> Self {
        fn generate_salt() -> [u8; 32] {
            StdRng::from_entropy().gen()
        }

        let magic_number = Self::MAGIC_NUMBER;
        let version = Version::V0;
        let salt = generate_salt();

        let checksum = Default::default();
        let mac = Default::default();

        Self {
            magic_number,
            version,
            params,
            salt,
            checksum,
            mac,
        }
    }

    /// Parses `data` into the header.
    pub fn parse(data: &[u8]) -> Result<Self, Error> {
        if data.len() < 128 {
            return Err(Error::InvalidLength);
        }

        let magic_number = if data[..6] == Self::MAGIC_NUMBER {
            Ok(Self::MAGIC_NUMBER)
        } else {
            Err(Error::InvalidMagicNumber)
        }?;
        let version = if data[6] == Version::V0.into() {
            Ok(Version::V0)
        } else {
            Err(Error::UnknownVersion(data[6]))
        }?;
        let log_n = data[7];
        let r = u32::from_be_bytes(
            data[8..12]
                .try_into()
                .expect("size of `r` parameter should be 4 bytes"),
        );
        let p = u32::from_be_bytes(
            data[12..16]
                .try_into()
                .expect("size of `p` parameter should be 4 bytes"),
        );
        let params = scrypt::Params::new(log_n, r, p, scrypt::Params::RECOMMENDED_LEN)
            .map_err(Error::from)?;
        let salt = data[16..48]
            .try_into()
            .expect("size of salt should be 32 bytes");

        let checksum = Default::default();
        let mac = Default::default();

        Ok(Self {
            magic_number,
            version,
            params,
            salt,
            checksum,
            mac,
        })
    }

    /// Gets a SHA-256 checksum of this header.
    pub fn compute_checksum(&mut self) {
        let result = Sha256::digest(&self.as_bytes()[..48]);
        self.checksum.copy_from_slice(&result[..16]);
    }

    /// Verifies a SHA-256 checksum stored in this header.
    pub fn verify_checksum(&mut self, checksum: &[u8]) -> Result<(), Error> {
        self.compute_checksum();
        if self.checksum == checksum {
            Ok(())
        } else {
            Err(Error::InvalidChecksum)
        }
    }

    /// Gets a HMAC-SHA-256 of this header.
    pub fn compute_mac(&mut self, key: &DerivedKey) {
        let mac = compute_mac(&key.mac(), &self.as_bytes()[..64]);
        self.mac.copy_from_slice(&mac);
    }

    /// Verifies a HMAC-SHA-256 stored in this header.
    pub fn verify_mac(&mut self, key: &DerivedKey, tag: &[u8]) -> Result<(), Error> {
        verify_mac(&key.mac(), &self.as_bytes()[..64], tag).map_err(Error::InvalidHeaderMac)?;
        self.mac.copy_from_slice(tag);
        Ok(())
    }

    /// Converts this header to a byte array.
    pub fn as_bytes(&self) -> [u8; Self::SIZE] {
        let mut header = [u8::default(); Self::SIZE];
        header[..6].copy_from_slice(&self.magic_number);
        header[6] = self.version.into();
        header[7] = self.params.log_n();
        header[8..12].copy_from_slice(&self.params.r().to_be_bytes());
        header[12..16].copy_from_slice(&self.params.p().to_be_bytes());
        header[16..48].copy_from_slice(&self.salt);

        header[48..64].copy_from_slice(&self.checksum);
        header[64..].copy_from_slice(&self.mac);

        header
    }

    /// Returns the scrypt parameters stored in this header.
    pub const fn params(&self) -> scrypt::Params {
        self.params
    }

    /// Returns a salt stored in this header.
    pub const fn salt(&self) -> [u8; 32] {
        self.salt
    }
}

/// Derived key.
#[derive(Clone, Debug)]
pub struct DerivedKey {
    encrypt: [u8; 32],
    mac: [u8; 32],
}

impl DerivedKey {
    /// Creates a new `DerivedKey`.
    pub fn new(dk: [u8; 64]) -> Self {
        let encrypt = dk[..32]
            .try_into()
            .expect("AES-256-CTR key size should be 256 bits");
        let mac = dk[32..]
            .try_into()
            .expect("HMAC-SHA-256 key size should be 256 bits");
        Self { encrypt, mac }
    }

    /// Returns the key for encrypted.
    pub const fn encrypt(&self) -> [u8; 32] {
        self.encrypt
    }

    /// Returns the key for a MAC.
    pub const fn mac(&self) -> [u8; 32] {
        self.mac
    }
}

/// The MAC (authentication tag) of the header.
#[derive(Clone, Debug)]
pub struct HeaderMac([u8; 32]);

impl HeaderMac {
    /// The number of bytes of the MAC.
    pub const SIZE: usize = mem::size_of::<Self>();

    /// Creates a new `HeaderMac`.
    pub const fn new(mac: [u8; Self::SIZE]) -> Self {
        Self(mac)
    }

    /// Converts this MAC to a byte array.
    pub const fn as_bytes(&self) -> [u8; Self::SIZE] {
        self.0
    }
}

/// Gets a HMAC-SHA-256.
pub fn compute_mac(key: &[u8], data: &[u8]) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key size should be 256 bits");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Verifies a HMAC-SHA-256.
pub fn verify_mac(key: &[u8], data: &[u8], tag: &[u8]) -> Result<(), MacError> {
    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 key size should be 256 bits");
    mac.update(data);
    mac.verify(tag.into())
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
        assert_eq!(str::from_utf8(&Header::MAGIC_NUMBER).unwrap(), "scrypt");
    }

    #[test]
    fn header_size() {
        assert_eq!(Header::SIZE, 96);
    }

    #[test]
    fn header_mac_size() {
        assert_eq!(HeaderMac::SIZE, 32);
    }
}
