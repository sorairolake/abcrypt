// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this crate.

use core::{fmt, result};

use blake2::digest::MacError;

/// The error type for the abcrypt encrypted data format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The encrypted data was shorter than 164 bytes.
    InvalidLength,

    /// The magic number (file signature) was invalid.
    InvalidMagicNumber,

    /// The version was the unsupported abcrypt version number.
    UnsupportedVersion(u8),

    /// The version was the unrecognized abcrypt version number.
    UnknownVersion(u8),

    /// The Argon2 type were invalid.
    InvalidArgon2Type(u32),

    /// The Argon2 version were invalid.
    InvalidArgon2Version(u32),

    /// The Argon2 parameters were invalid.
    InvalidArgon2Params(argon2::Error),

    /// The Argon2 context was invalid.
    InvalidArgon2Context(argon2::Error),

    /// The MAC (authentication tag) of the header was invalid.
    InvalidHeaderMac(MacError),

    /// The MAC (authentication tag) of the ciphertext was invalid.
    InvalidMac(chacha20poly1305::Error),
}

impl fmt::Display for Error {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "encrypted data is shorter than 164 bytes"),
            Self::InvalidMagicNumber => write!(f, "invalid magic number"),
            Self::UnsupportedVersion(version) => {
                write!(f, "unsupported version number `{version}`")
            }
            Self::UnknownVersion(version) => write!(f, "unknown version number `{version}`"),
            Self::InvalidArgon2Type(_) => write!(f, "invalid Argon2 type"),
            Self::InvalidArgon2Version(version) => {
                write!(f, "invalid Argon2 version `{version:#x}`")
            }
            Self::InvalidArgon2Params(_) => write!(f, "invalid Argon2 parameters"),
            Self::InvalidArgon2Context(_) => write!(f, "invalid Argon2 context"),
            Self::InvalidHeaderMac(_) => write!(f, "invalid header MAC"),
            Self::InvalidMac(_) => write!(f, "invalid ciphertext MAC"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidArgon2Params(err) | Self::InvalidArgon2Context(err) => Some(err),
            Self::InvalidHeaderMac(err) => Some(err),
            Self::InvalidMac(err) => Some(err),
            _ => None,
        }
    }
}

impl From<MacError> for Error {
    #[inline]
    fn from(err: MacError) -> Self {
        Self::InvalidHeaderMac(err)
    }
}

impl From<chacha20poly1305::Error> for Error {
    #[inline]
    fn from(err: chacha20poly1305::Error) -> Self {
        Self::InvalidMac(err)
    }
}

/// A specialized [`Result`](result::Result) type for read and write operations
/// for the abcrypt encrypted data format.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "alloc")]
/// # {
/// use abcrypt::{Decryptor, Encryptor};
///
/// fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> abcrypt::Result<Vec<u8>> {
///     Encryptor::new(&plaintext, passphrase).map(|c| c.encrypt_to_vec())
/// }
///
/// fn decrypt(ciphertext: &[u8], passphrase: &[u8]) -> abcrypt::Result<Vec<u8>> {
///     Decryptor::new(&ciphertext, passphrase).and_then(|c| c.decrypt_to_vec())
/// }
///
/// let data = b"Hello, world!\n";
/// let passphrase = b"passphrase";
///
/// let ciphertext = encrypt(data, passphrase).unwrap();
/// assert_ne!(ciphertext, data);
///
/// let plaintext = decrypt(&ciphertext, passphrase).unwrap();
/// assert_eq!(plaintext, data);
/// # }
/// ```
pub type Result<T> = result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone() {
        assert_eq!(Error::InvalidLength.clone(), Error::InvalidLength);
        assert_eq!(Error::InvalidMagicNumber.clone(), Error::InvalidMagicNumber);
        assert_eq!(
            Error::UnsupportedVersion(u8::MIN).clone(),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_eq!(
            Error::UnknownVersion(u8::MAX).clone(),
            Error::UnknownVersion(u8::MAX)
        );
        assert_eq!(
            Error::InvalidArgon2Type(u32::MAX).clone(),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_eq!(
            Error::InvalidArgon2Version(u32::MAX).clone(),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_eq!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong).clone(),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_eq!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong).clone(),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_eq!(
            Error::InvalidHeaderMac(MacError).clone(),
            Error::InvalidHeaderMac(MacError)
        );
        assert_eq!(
            Error::InvalidMac(chacha20poly1305::Error).clone(),
            Error::InvalidMac(chacha20poly1305::Error)
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
            let a = Error::UnsupportedVersion(u8::MIN);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::UnknownVersion(u8::MAX);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidArgon2Type(u32::MAX);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidArgon2Version(u32::MAX);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidArgon2Params(argon2::Error::AdTooLong);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidArgon2Context(argon2::Error::AdTooLong);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidHeaderMac(MacError);
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = Error::InvalidMac(chacha20poly1305::Error);
            let b = a;
            assert_eq!(a, b);
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn debug() {
        assert_eq!(format!("{:?}", Error::InvalidLength), "InvalidLength");
        assert_eq!(
            format!("{:?}", Error::InvalidMagicNumber),
            "InvalidMagicNumber"
        );
        assert_eq!(
            format!("{:?}", Error::UnsupportedVersion(u8::MIN)),
            "UnsupportedVersion(0)"
        );
        assert_eq!(
            format!("{:?}", Error::UnknownVersion(u8::MAX)),
            "UnknownVersion(255)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidArgon2Type(u32::MAX)),
            "InvalidArgon2Type(4294967295)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidArgon2Version(u32::MAX)),
            "InvalidArgon2Version(4294967295)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidArgon2Params(argon2::Error::AdTooLong)),
            "InvalidArgon2Params(AdTooLong)"
        );
        assert_eq!(
            format!(
                "{:?}",
                Error::InvalidArgon2Context(argon2::Error::AdTooLong)
            ),
            "InvalidArgon2Context(AdTooLong)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidHeaderMac(MacError)),
            "InvalidHeaderMac(MacError)"
        );
        assert_eq!(
            format!("{:?}", Error::InvalidMac(chacha20poly1305::Error)),
            "InvalidMac(Error)"
        );
    }

    #[test]
    fn equality() {
        assert_eq!(Error::InvalidLength, Error::InvalidLength);
        assert_ne!(Error::InvalidLength, Error::InvalidMagicNumber);
        assert_ne!(Error::InvalidLength, Error::UnsupportedVersion(u8::MIN));
        assert_ne!(Error::InvalidLength, Error::UnknownVersion(u8::MAX));
        assert_ne!(Error::InvalidLength, Error::InvalidArgon2Type(u32::MAX));
        assert_ne!(Error::InvalidLength, Error::InvalidArgon2Version(u32::MAX));
        assert_ne!(
            Error::InvalidLength,
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidLength,
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(Error::InvalidLength, Error::InvalidHeaderMac(MacError));
        assert_ne!(
            Error::InvalidLength,
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidLength);
        assert_eq!(Error::InvalidMagicNumber, Error::InvalidMagicNumber);
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(Error::InvalidMagicNumber, Error::UnknownVersion(u8::MAX));
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(Error::InvalidMagicNumber, Error::InvalidHeaderMac(MacError));
        assert_ne!(
            Error::InvalidMagicNumber,
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(Error::UnsupportedVersion(u8::MIN), Error::InvalidLength);
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidMagicNumber
        );
        assert_eq!(
            Error::UnsupportedVersion(u8::MIN),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::UnsupportedVersion(u8::MIN),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidLength);
        assert_ne!(Error::UnknownVersion(u8::MAX), Error::InvalidMagicNumber);
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_eq!(
            Error::UnknownVersion(u8::MAX),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::UnknownVersion(u8::MAX),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(Error::InvalidArgon2Type(u32::MAX), Error::InvalidLength);
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::UnknownVersion(u8::MAX)
        );
        assert_eq!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidArgon2Type(u32::MAX),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(Error::InvalidArgon2Version(u32::MAX), Error::InvalidLength);
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_eq!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidArgon2Version(u32::MAX),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidLength
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_eq!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidLength
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_eq!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidLength);
        assert_ne!(Error::InvalidHeaderMac(MacError), Error::InvalidMagicNumber);
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_eq!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidHeaderMac(MacError)
        );
        assert_ne!(
            Error::InvalidHeaderMac(MacError),
            Error::InvalidMac(chacha20poly1305::Error)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidLength
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidMagicNumber
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::UnsupportedVersion(u8::MIN)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::UnknownVersion(u8::MAX)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidArgon2Type(u32::MAX)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidArgon2Version(u32::MAX)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
        );
        assert_ne!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidHeaderMac(MacError)
        );
        assert_eq!(
            Error::InvalidMac(chacha20poly1305::Error),
            Error::InvalidMac(chacha20poly1305::Error)
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn display() {
        assert_eq!(
            format!("{}", Error::InvalidLength),
            "encrypted data is shorter than 164 bytes"
        );
        assert_eq!(
            format!("{}", Error::InvalidMagicNumber),
            "invalid magic number"
        );
        assert_eq!(
            format!("{}", Error::UnsupportedVersion(u8::MIN)),
            "unsupported version number `0`"
        );
        assert_eq!(
            format!("{}", Error::UnknownVersion(u8::MAX)),
            "unknown version number `255`"
        );
        assert_eq!(
            format!("{}", Error::InvalidArgon2Type(u32::MAX)),
            "invalid Argon2 type"
        );
        assert_eq!(
            format!("{}", Error::InvalidArgon2Version(u32::MAX)),
            "invalid Argon2 version `0xffffffff`"
        );
        assert_eq!(
            format!("{}", Error::InvalidArgon2Params(argon2::Error::AdTooLong)),
            "invalid Argon2 parameters"
        );
        assert_eq!(
            format!("{}", Error::InvalidArgon2Context(argon2::Error::AdTooLong)),
            "invalid Argon2 context"
        );
        assert_eq!(
            format!("{}", Error::InvalidHeaderMac(MacError)),
            "invalid header MAC"
        );
        assert_eq!(
            format!("{}", Error::InvalidMac(chacha20poly1305::Error)),
            "invalid ciphertext MAC"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn source() {
        use std::error::Error as _;

        assert!(Error::InvalidLength.source().is_none());
        assert!(Error::InvalidMagicNumber.source().is_none());
        assert!(Error::UnsupportedVersion(u8::MIN).source().is_none());
        assert!(Error::UnknownVersion(u8::MAX).source().is_none());
        assert!(Error::InvalidArgon2Type(u32::MAX).source().is_none());
        assert!(Error::InvalidArgon2Version(u32::MAX).source().is_none());
        assert!(
            Error::InvalidArgon2Params(argon2::Error::AdTooLong)
                .source()
                .unwrap()
                .is::<argon2::Error>()
        );
        assert!(
            Error::InvalidArgon2Context(argon2::Error::AdTooLong)
                .source()
                .unwrap()
                .is::<argon2::Error>()
        );
        assert!(
            Error::InvalidHeaderMac(MacError)
                .source()
                .unwrap()
                .is::<MacError>()
        );
        assert!(
            Error::InvalidMac(chacha20poly1305::Error)
                .source()
                .unwrap()
                .is::<chacha20poly1305::Error>()
        );
    }

    #[test]
    fn from_mac_error_to_error() {
        assert_eq!(Error::from(MacError), Error::InvalidHeaderMac(MacError));
    }

    #[test]
    fn from_chacha20poly1305_error_to_error() {
        assert_eq!(
            Error::from(chacha20poly1305::Error),
            Error::InvalidMac(chacha20poly1305::Error)
        );
    }

    #[test]
    fn result_type() {
        use core::any;

        assert_eq!(
            any::type_name::<Result<()>>(),
            any::type_name::<result::Result<(), Error>>()
        );
        assert_eq!(
            any::type_name::<Result<u8>>(),
            any::type_name::<result::Result<u8, Error>>()
        );
    }
}
