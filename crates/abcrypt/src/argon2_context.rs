// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 context.

use argon2::Algorithm;

use crate::{format::Header, Error, Result};

/// The Argon2 context used for the encrypted data.
#[derive(Clone, Copy, Debug)]
pub struct Argon2 {
    variant: Algorithm,
    version: argon2::Version,
}

impl Argon2 {
    /// Creates a new instance of the Argon2 context from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 164 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unsupported abcrypt version number.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 type is invalid.
    /// - The Argon2 version is invalid.
    /// - The Argon2 parameters are invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::Argon2;
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// assert!(Argon2::new(ciphertext).is_ok());
    /// ```
    #[inline]
    pub fn new(ciphertext: impl AsRef<[u8]>) -> Result<Self> {
        let inner = |ciphertext: &[u8]| -> Result<Self> {
            let header = Header::parse(ciphertext)?;
            let variant = header.argon2_type().into();
            let version = header.argon2_version().into();
            Ok(Self { variant, version })
        };
        inner(ciphertext.as_ref())
    }

    /// Gets the Argon2 type.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Algorithm, Argon2};
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// let argon2 = Argon2::new(ciphertext).unwrap();
    /// assert_eq!(argon2.variant(), Algorithm::Argon2id);
    /// ```
    #[must_use]
    #[inline]
    pub const fn variant(&self) -> Algorithm {
        self.variant
    }

    /// Gets the Argon2 version.
    ///
    /// # Examples
    ///
    /// ```
    /// # use abcrypt::{argon2::Version, Argon2};
    /// #
    /// let ciphertext = include_bytes!("../tests/data/v1/data.txt.abcrypt");
    ///
    /// let argon2 = Argon2::new(ciphertext).unwrap();
    /// assert_eq!(argon2.version(), Version::V0x13);
    /// ```
    #[must_use]
    #[inline]
    pub const fn version(&self) -> argon2::Version {
        self.version
    }
}

/// Type of Argon2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Variant {
    /// Argon2d.
    Argon2d,

    /// Argon2i.
    Argon2i,

    /// Argon2id.
    Argon2id,
}

impl From<Variant> for u32 {
    #[inline]
    fn from(variant: Variant) -> Self {
        variant as Self
    }
}

impl From<Variant> for Algorithm {
    #[inline]
    fn from(variant: Variant) -> Self {
        match variant {
            Variant::Argon2d => Self::Argon2d,
            Variant::Argon2i => Self::Argon2i,
            Variant::Argon2id => Self::Argon2id,
        }
    }
}

impl TryFrom<u32> for Variant {
    type Error = Error;

    #[inline]
    fn try_from(variant: u32) -> Result<Self> {
        match variant {
            0 => Ok(Self::Argon2d),
            1 => Ok(Self::Argon2i),
            2 => Ok(Self::Argon2id),
            v => Err(Error::InvalidArgon2Type(v)),
        }
    }
}

impl From<Algorithm> for Variant {
    #[inline]
    fn from(algorithm: Algorithm) -> Self {
        match algorithm {
            Algorithm::Argon2d => Self::Argon2d,
            Algorithm::Argon2i => Self::Argon2i,
            Algorithm::Argon2id => Self::Argon2id,
        }
    }
}

/// Version of Argon2.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Version {
    /// Version 0x10.
    V0x10 = 0x10,

    /// Version 0x13.
    V0x13 = 0x13,
}

impl From<Version> for u32 {
    #[inline]
    fn from(version: Version) -> Self {
        version as Self
    }
}

impl From<Version> for argon2::Version {
    #[inline]
    fn from(version: Version) -> Self {
        match version {
            Version::V0x10 => Self::V0x10,
            Version::V0x13 => Self::V0x13,
        }
    }
}

impl TryFrom<u32> for Version {
    type Error = Error;

    #[inline]
    fn try_from(version: u32) -> Result<Self> {
        match version {
            0x10 => Ok(Self::V0x10),
            0x13 => Ok(Self::V0x13),
            v => Err(Error::InvalidArgon2Version(v)),
        }
    }
}

impl From<argon2::Version> for Version {
    #[inline]
    fn from(version: argon2::Version) -> Self {
        match version {
            argon2::Version::V0x10 => Self::V0x10,
            argon2::Version::V0x13 => Self::V0x13,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_variant_to_u32() {
        assert_eq!(u32::from(Variant::Argon2d), 0);
        assert_eq!(u32::from(Variant::Argon2i), 1);
        assert_eq!(u32::from(Variant::Argon2id), 2);
    }

    #[test]
    fn from_variant_to_algorithm() {
        assert_eq!(Algorithm::from(Variant::Argon2d), Algorithm::Argon2d);
        assert_eq!(Algorithm::from(Variant::Argon2i), Algorithm::Argon2i);
        assert_eq!(Algorithm::from(Variant::Argon2id), Algorithm::Argon2id);
    }

    #[test]
    fn try_from_u32_to_variant() {
        assert_eq!(Variant::try_from(0).unwrap(), Variant::Argon2d);
        assert_eq!(Variant::try_from(1).unwrap(), Variant::Argon2i);
        assert_eq!(Variant::try_from(2).unwrap(), Variant::Argon2id);
    }

    #[test]
    fn try_from_u32_to_variant_with_invalid_argon2_type() {
        assert_eq!(
            Variant::try_from(3).unwrap_err(),
            Error::InvalidArgon2Type(3)
        );
        assert_eq!(
            Variant::try_from(u32::MAX).unwrap_err(),
            Error::InvalidArgon2Type(u32::MAX)
        );
    }

    #[test]
    fn from_algorithm_to_variant() {
        assert_eq!(Variant::from(Algorithm::Argon2d), Variant::Argon2d);
        assert_eq!(Variant::from(Algorithm::Argon2i), Variant::Argon2i);
        assert_eq!(Variant::from(Algorithm::Argon2id), Variant::Argon2id);
    }

    #[test]
    fn from_version_to_u32() {
        assert_eq!(u32::from(Version::V0x10), 0x10);
        assert_eq!(u32::from(Version::V0x13), 0x13);
    }

    #[test]
    fn from_version_to_argon2_version() {
        assert_eq!(
            argon2::Version::from(Version::V0x10),
            argon2::Version::V0x10
        );
        assert_eq!(
            argon2::Version::from(Version::V0x13),
            argon2::Version::V0x13
        );
    }

    #[test]
    fn try_from_u32_to_version() {
        assert_eq!(Version::try_from(0x10).unwrap(), Version::V0x10);
        assert_eq!(Version::try_from(0x13).unwrap(), Version::V0x13);
    }

    #[test]
    fn try_from_u32_to_version_with_invalid_argon2_version() {
        assert_eq!(
            Version::try_from(u32::MIN).unwrap_err(),
            Error::InvalidArgon2Version(u32::MIN)
        );
        assert_eq!(
            Version::try_from(0xf).unwrap_err(),
            Error::InvalidArgon2Version(0xf)
        );
        assert_eq!(
            Version::try_from(0x11).unwrap_err(),
            Error::InvalidArgon2Version(0x11)
        );
        assert_eq!(
            Version::try_from(0x12).unwrap_err(),
            Error::InvalidArgon2Version(0x12)
        );
        assert_eq!(
            Version::try_from(0x14).unwrap_err(),
            Error::InvalidArgon2Version(0x14)
        );
        assert_eq!(
            Version::try_from(u32::MAX).unwrap_err(),
            Error::InvalidArgon2Version(u32::MAX)
        );
    }

    #[test]
    fn from_argon2_version_to_version() {
        assert_eq!(Version::from(argon2::Version::V0x10), Version::V0x10);
        assert_eq!(Version::from(argon2::Version::V0x13), Version::V0x13);
    }
}
