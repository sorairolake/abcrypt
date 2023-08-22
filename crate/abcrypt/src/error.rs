// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this crate.

use core::fmt;

use hmac::digest::MacError;
use scrypt::errors::InvalidParams;

/// The error type for the scrypt encrypted data format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The encrypted data was shorter than 128 bytes.
    InvalidLength,

    /// The magic number (file signature) was invalid.
    InvalidMagicNumber,

    /// The version was the unrecognized scrypt version number.
    UnknownVersion(u8),

    /// The scrypt parameters were invalid.
    InvalidParams(InvalidParams),

    /// The checksum of the header mismatched.
    InvalidChecksum,

    /// The MAC (authentication tag) of the header was invalid.
    InvalidHeaderMac(MacError),

    /// The MAC (authentication tag) at EOF was invalid.
    InvalidMac(MacError),
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "encrypted data is shorter than 128 bytes"),
            Self::InvalidMagicNumber => write!(f, "invalid magic number"),
            Self::UnknownVersion(version) => write!(f, "unknown version number `{version}`"),
            Self::InvalidParams(err) => write!(f, "{err}"),
            Self::InvalidChecksum => write!(f, "checksum mismatch"),
            Self::InvalidHeaderMac(_) => write!(f, "invalid header MAC"),
            Self::InvalidMac(_) => write!(f, "invalid MAC"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidHeaderMac(err) | Self::InvalidMac(err) => Some(err),
            _ => None,
        }
    }
}

impl From<InvalidParams> for Error {
    #[inline]
    fn from(source: InvalidParams) -> Self {
        Self::InvalidParams(source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone() {
        assert_eq!(Error::InvalidLength.clone(), Error::InvalidLength);
        assert_eq!(Error::InvalidMagicNumber.clone(), Error::InvalidMagicNumber);
        assert_eq!(
            Error::UnknownVersion(u8::MAX).clone(),
            Error::UnknownVersion(u8::MAX)
        );
        assert_eq!(
            Error::InvalidParams(InvalidParams).clone(),
            Error::InvalidParams(InvalidParams)
        );
        assert_eq!(Error::InvalidChecksum.clone(), Error::InvalidChecksum);
        assert_eq!(
            Error::InvalidHeaderMac(MacError).clone(),
            Error::InvalidHeaderMac(MacError)
        );
        assert_eq!(
            Error::InvalidMac(MacError).clone(),
            Error::InvalidMac(MacError)
        );
    }

    #[test]
    fn copy() {
        {
            let a = Error::InvalidLength;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidMagicNumber;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::UnknownVersion(u8::MAX);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidParams(InvalidParams);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidChecksum;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidHeaderMac(MacError);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidMac(MacError);
            let b = a;
            assert_eq!(a, b);
        }
    }

    #[test]
    fn debug() {
        assert_eq!(format!("{:?}", Error::InvalidLength), "InvalidLength");
        assert_eq!(
            format!("{:?}", Error::InvalidMagicNumber),
            "InvalidMagicNumber"
        );
        assert_eq!(
            format!("{:?}", Error::UnknownVersion(u8::MAX)),
            "UnknownVersion(255)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidParams(InvalidParams)),
            "InvalidParams(InvalidParams)"
        );
        assert_eq!(format!("{:?}", Error::InvalidChecksum), "InvalidChecksum");
        assert_eq!(
            format!("{:?}", Error::InvalidHeaderMac(MacError)),
            "InvalidHeaderMac(MacError)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidMac(MacError)),
            "InvalidMac(MacError)"
        );
    }

    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    #[test]
    fn equality() {
        assert_eq!(Error::InvalidLength, Error::InvalidLength);
        assert_ne!(Error::InvalidLength, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidLength, Error::UnknownVersion(u8::MAX));
        assert_ne!(Error::InvalidLength, Error::InvalidParams(InvalidParams));
        assert_ne!(Error::InvalidLength, Error::InvalidChecksum);
        assert_ne!(Error::InvalidLength, Error::InvalidHeaderMac(MacError));
        assert_ne!(Error::InvalidLength, Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidLength);
        assert_eq!(Error::InvalidMagicNumber, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidMagicNumber, Error::UnknownVersion(u8::MAX));
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidChecksum);
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidHeaderMac(MacError));
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidMac(MacError));
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidLength);
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidMagicNumber);
        assert_eq!(
            Error::UnknownVersion(u8::MAX),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidChecksum);
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidParams(InvalidParams), Error::InvalidLength);
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::UnknownVersion(u8::MAX)
        );
        assert_eq!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidParams(InvalidParams), Error::InvalidChecksum);
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidParams(InvalidParams),
            Error::InvalidMac(MacError)
        );
        assert_ne!(Error::InvalidChecksum, Error::InvalidLength);
        assert_ne!(Error::InvalidChecksum, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidChecksum, Error::UnknownVersion(u8::MAX));
        assert_ne!(Error::InvalidChecksum, Error::InvalidParams(InvalidParams));
        assert_eq!(Error::InvalidChecksum, Error::InvalidChecksum);
        assert_ne!(Error::InvalidChecksum, Error::InvalidHeaderMac(MacError));
        assert_ne!(Error::InvalidChecksum, Error::InvalidMac(MacError));
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidLength);
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidMagicNumber);
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidChecksum);
        assert_eq!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidMac(MacError)
        );
        assert_ne!(Error::InvalidMac(MacError), Error::InvalidLength);
        assert_ne!(Error::InvalidMac(MacError), Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidMac(MacError), Error::UnknownVersion(u8::MAX));
        assert_ne!(
            Error::InvalidMac(MacError),
            Error::InvalidParams(InvalidParams)
        );
        assert_ne!(Error::InvalidMac(MacError), Error::InvalidChecksum);
        assert_ne!(
            Error::InvalidMac(MacError),
            Error::InvalidHeaderMac(MacError)
        );
        assert_eq!(Error::InvalidMac(MacError), Error::InvalidMac(MacError));
    }

    #[test]
    fn display() {
        assert_eq!(
            format!("{}", Error::InvalidLength),
            "encrypted data is shorter than 128 bytes"
        );
        assert_eq!(
            format!("{}", Error::InvalidMagicNumber),
            "invalid magic number"
        );
        assert_eq!(
            format!("{}", Error::UnknownVersion(u8::MAX)),
            "unknown version number `255`"
        );
        assert_eq!(
            format!("{}", Error::InvalidParams(InvalidParams)),
            "invalid scrypt parameters"
        );
        assert_eq!(format!("{}", Error::InvalidChecksum), "checksum mismatch");
        assert_eq!(
            format!("{}", Error::InvalidHeaderMac(MacError)),
            "invalid header MAC"
        );
        assert_eq!(format!("{}", Error::InvalidMac(MacError)), "invalid MAC");
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        use std::error::Error as _;

        assert!(Error::InvalidLength.source().is_none());
        assert!(Error::InvalidMagicNumber.source().is_none());
        assert!(Error::UnknownVersion(u8::MAX).source().is_none());
        assert!(Error::InvalidParams(InvalidParams).source().is_none());
        assert!(Error::InvalidChecksum.source().is_none());
        assert!(Error::InvalidHeaderMac(MacError)
            .source()
            .unwrap()
            .is::<MacError>());
        assert!(Error::InvalidMac(MacError)
            .source()
            .unwrap()
            .is::<MacError>());
    }

    #[test]
    fn from_invalid_params_to_error() {
        assert_eq!(
            Error::from(InvalidParams),
            Error::InvalidParams(InvalidParams)
        );
    }
}
