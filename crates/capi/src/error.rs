// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this crate.

use std::{ffi::CString, fmt, ptr::NonNull, slice};

use abcrypt::Error;

/// The error code for the abcrypt encrypted data format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::module_name_repetitions)]
#[repr(C)]
pub enum ErrorCode {
    /// Everything is ok.
    Ok,

    /// General error.
    Error,

    /// The encrypted data was shorter than 156 bytes.
    InvalidLength,

    /// The magic number (file signature) was invalid.
    InvalidMagicNumber,

    /// The version was the unrecognized abcrypt version number.
    UnknownVersion,

    /// The Argon2 parameters were invalid.
    InvalidArgon2Params,

    /// The Argon2 context was invalid.
    InvalidArgon2Context,

    /// The MAC (authentication tag) of the header was invalid.
    InvalidHeaderMac,

    /// The MAC (authentication tag) of the ciphertext was invalid.
    InvalidMac,
}

impl ErrorCode {
    #[allow(clippy::missing_panics_doc)]
    /// Gets a detailed error message.
    ///
    /// # Errors
    ///
    /// Returns an error if `buf` is null.
    ///
    /// # Safety
    ///
    /// Behavior is undefined if `buf` and `buf_len` violates the safety
    /// conditions of `slice::from_raw_parts`.
    #[must_use]
    unsafe fn error_message(self, buf: Option<NonNull<u8>>, buf_len: usize) -> Self {
        let message = CString::new(self.to_string())
            .expect("error message should not contain the null character");
        let message = message.as_bytes_with_nul();
        let Some(buf) = buf else { return Self::Error };
        // SAFETY: just checked that `buf` is not a null pointer.
        let buf = unsafe { slice::from_raw_parts_mut(buf.as_ptr(), buf_len) };
        buf.copy_from_slice(message);
        Self::Ok
    }

    /// Returns the number of output bytes of the error message.
    fn error_message_out_len(self) -> usize {
        CString::new(self.to_string())
            .expect("error message should not contain the null character")
            .as_bytes_with_nul()
            .len()
    }
}

impl fmt::Display for ErrorCode {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => write!(f, "everything is ok"),
            Self::Error => write!(f, "general error"),
            Self::InvalidLength => write!(f, "{}", Error::InvalidLength),
            Self::InvalidMagicNumber => write!(f, "{}", Error::InvalidMagicNumber),
            Self::UnknownVersion => write!(f, "unknown version number"),
            Self::InvalidArgon2Params => write!(f, "invalid Argon2 parameters"),
            Self::InvalidArgon2Context => write!(f, "invalid Argon2 context"),
            Self::InvalidHeaderMac => write!(f, "invalid header MAC"),
            Self::InvalidMac => write!(f, "invalid ciphertext MAC"),
        }
    }
}

impl From<Error> for ErrorCode {
    #[inline]
    fn from(error: Error) -> Self {
        match error {
            Error::InvalidLength => Self::InvalidLength,
            Error::InvalidMagicNumber => Self::InvalidMagicNumber,
            Error::UnknownVersion(_) => Self::UnknownVersion,
            Error::InvalidArgon2Params(_) => Self::InvalidArgon2Params,
            Error::InvalidArgon2Context(_) => Self::InvalidArgon2Context,
            Error::InvalidHeaderMac(_) => Self::InvalidHeaderMac,
            Error::InvalidMac(_) => Self::InvalidMac,
        }
    }
}

#[allow(clippy::missing_panics_doc)]
/// Gets a detailed error message.
///
/// # Errors
///
/// Returns an error if `buf` is null.
///
/// # Safety
///
/// Behavior is undefined if `buf` and `buf_len` violates the safety conditions
/// of `slice::from_raw_parts`.
#[must_use]
#[no_mangle]
pub unsafe extern "C-unwind" fn abcrypt_error_message(
    error_code: ErrorCode,
    buf: Option<NonNull<u8>>,
    buf_len: usize,
) -> ErrorCode {
    ErrorCode::error_message(error_code, buf, buf_len)
}

/// Returns the number of output bytes of the error message.
#[no_mangle]
pub extern "C-unwind" fn abcrypt_error_message_out_len(error_code: ErrorCode) -> usize {
    error_code.error_message_out_len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code() {
        use std::ffi::c_int;

        assert_eq!(ErrorCode::Ok as c_int, 0);
        assert_eq!(ErrorCode::Error as c_int, 1);
        assert_eq!(ErrorCode::InvalidLength as c_int, 2);
        assert_eq!(ErrorCode::InvalidMagicNumber as c_int, 3);
        assert_eq!(ErrorCode::UnknownVersion as c_int, 4);
        assert_eq!(ErrorCode::InvalidArgon2Params as c_int, 5);
        assert_eq!(ErrorCode::InvalidArgon2Context as c_int, 6);
        assert_eq!(ErrorCode::InvalidHeaderMac as c_int, 7);
        assert_eq!(ErrorCode::InvalidMac as c_int, 8);
    }

    #[test]
    fn clone() {
        assert_eq!(ErrorCode::Ok.clone(), ErrorCode::Ok);
        assert_eq!(ErrorCode::Error.clone(), ErrorCode::Error);
        assert_eq!(ErrorCode::InvalidLength.clone(), ErrorCode::InvalidLength);
        assert_eq!(
            ErrorCode::InvalidMagicNumber.clone(),
            ErrorCode::InvalidMagicNumber
        );
        assert_eq!(ErrorCode::UnknownVersion.clone(), ErrorCode::UnknownVersion);
        assert_eq!(
            ErrorCode::InvalidArgon2Params.clone(),
            ErrorCode::InvalidArgon2Params
        );
        assert_eq!(
            ErrorCode::InvalidArgon2Context.clone(),
            ErrorCode::InvalidArgon2Context
        );
        assert_eq!(
            ErrorCode::InvalidHeaderMac.clone(),
            ErrorCode::InvalidHeaderMac
        );
        assert_eq!(ErrorCode::InvalidMac.clone(), ErrorCode::InvalidMac);
    }

    #[test]
    fn copy() {
        {
            let a = ErrorCode::Ok;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::Error;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::InvalidLength;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::InvalidMagicNumber;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::UnknownVersion;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::InvalidArgon2Params;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::InvalidArgon2Context;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::InvalidHeaderMac;
            let b = a;
            assert_eq!(a, b);
        }

        {
            let a = ErrorCode::InvalidMac;
            let b = a;
            assert_eq!(a, b);
        }
    }

    #[test]
    fn debug() {
        assert_eq!(format!("{:?}", ErrorCode::Ok), "Ok");
        assert_eq!(format!("{:?}", ErrorCode::Error), "Error");
        assert_eq!(format!("{:?}", ErrorCode::InvalidLength), "InvalidLength");
        assert_eq!(
            format!("{:?}", ErrorCode::InvalidMagicNumber),
            "InvalidMagicNumber"
        );
        assert_eq!(format!("{:?}", ErrorCode::UnknownVersion), "UnknownVersion");
        assert_eq!(
            format!("{:?}", ErrorCode::InvalidArgon2Params),
            "InvalidArgon2Params"
        );
        assert_eq!(
            format!("{:?}", ErrorCode::InvalidArgon2Context),
            "InvalidArgon2Context"
        );
        assert_eq!(
            format!("{:?}", ErrorCode::InvalidHeaderMac),
            "InvalidHeaderMac"
        );
        assert_eq!(format!("{:?}", ErrorCode::InvalidMac), "InvalidMac");
    }

    #[test]
    #[allow(clippy::cognitive_complexity, clippy::too_many_lines)]
    fn equality() {
        assert_eq!(ErrorCode::Ok, ErrorCode::Ok);
        assert_ne!(ErrorCode::Ok, ErrorCode::Error);
        assert_ne!(ErrorCode::Ok, ErrorCode::InvalidLength);
        assert_ne!(ErrorCode::Ok, ErrorCode::InvalidMagicNumber);
        assert_ne!(ErrorCode::Ok, ErrorCode::UnknownVersion);
        assert_ne!(ErrorCode::Ok, ErrorCode::InvalidArgon2Params);
        assert_ne!(ErrorCode::Ok, ErrorCode::InvalidArgon2Context);
        assert_ne!(ErrorCode::Ok, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::Ok, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::Error, ErrorCode::Ok);
        assert_eq!(ErrorCode::Error, ErrorCode::Error);
        assert_ne!(ErrorCode::Error, ErrorCode::InvalidLength);
        assert_ne!(ErrorCode::Error, ErrorCode::InvalidMagicNumber);
        assert_ne!(ErrorCode::Error, ErrorCode::UnknownVersion);
        assert_ne!(ErrorCode::Error, ErrorCode::InvalidArgon2Params);
        assert_ne!(ErrorCode::Error, ErrorCode::InvalidArgon2Context);
        assert_ne!(ErrorCode::Error, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::Error, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::Ok);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::Error);
        assert_eq!(ErrorCode::InvalidLength, ErrorCode::InvalidLength);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::InvalidMagicNumber);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::UnknownVersion);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::InvalidArgon2Params);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::InvalidArgon2Context);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::InvalidLength, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::InvalidMagicNumber, ErrorCode::Ok);
        assert_ne!(ErrorCode::InvalidMagicNumber, ErrorCode::Error);
        assert_ne!(ErrorCode::InvalidMagicNumber, ErrorCode::InvalidLength);
        assert_eq!(ErrorCode::InvalidMagicNumber, ErrorCode::InvalidMagicNumber);
        assert_ne!(ErrorCode::InvalidMagicNumber, ErrorCode::UnknownVersion);
        assert_ne!(
            ErrorCode::InvalidMagicNumber,
            ErrorCode::InvalidArgon2Params
        );
        assert_ne!(
            ErrorCode::InvalidMagicNumber,
            ErrorCode::InvalidArgon2Context
        );
        assert_ne!(ErrorCode::InvalidMagicNumber, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::InvalidMagicNumber, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::Ok);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::Error);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::InvalidLength);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::InvalidMagicNumber);
        assert_eq!(ErrorCode::UnknownVersion, ErrorCode::UnknownVersion);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::InvalidArgon2Params);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::InvalidArgon2Context);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::UnknownVersion, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::InvalidArgon2Params, ErrorCode::Ok);
        assert_ne!(ErrorCode::InvalidArgon2Params, ErrorCode::Error);
        assert_ne!(ErrorCode::InvalidArgon2Params, ErrorCode::InvalidLength);
        assert_ne!(
            ErrorCode::InvalidArgon2Params,
            ErrorCode::InvalidMagicNumber
        );
        assert_ne!(ErrorCode::InvalidArgon2Params, ErrorCode::UnknownVersion);
        assert_eq!(
            ErrorCode::InvalidArgon2Params,
            ErrorCode::InvalidArgon2Params
        );
        assert_ne!(
            ErrorCode::InvalidArgon2Params,
            ErrorCode::InvalidArgon2Context
        );
        assert_ne!(ErrorCode::InvalidArgon2Params, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::InvalidArgon2Params, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::InvalidArgon2Context, ErrorCode::Ok);
        assert_ne!(ErrorCode::InvalidArgon2Context, ErrorCode::Error);
        assert_ne!(ErrorCode::InvalidArgon2Context, ErrorCode::InvalidLength);
        assert_ne!(
            ErrorCode::InvalidArgon2Context,
            ErrorCode::InvalidMagicNumber
        );
        assert_ne!(ErrorCode::InvalidArgon2Context, ErrorCode::UnknownVersion);
        assert_ne!(
            ErrorCode::InvalidArgon2Context,
            ErrorCode::InvalidArgon2Params
        );
        assert_eq!(
            ErrorCode::InvalidArgon2Context,
            ErrorCode::InvalidArgon2Context
        );
        assert_ne!(ErrorCode::InvalidArgon2Context, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::InvalidArgon2Context, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::Ok);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::Error);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::InvalidLength);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::InvalidMagicNumber);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::UnknownVersion);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::InvalidArgon2Params);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::InvalidArgon2Context);
        assert_eq!(ErrorCode::InvalidHeaderMac, ErrorCode::InvalidHeaderMac);
        assert_ne!(ErrorCode::InvalidHeaderMac, ErrorCode::InvalidMac);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::Ok);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::Error);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::InvalidLength);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::InvalidMagicNumber);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::UnknownVersion);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::InvalidArgon2Params);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::InvalidArgon2Context);
        assert_ne!(ErrorCode::InvalidMac, ErrorCode::InvalidHeaderMac);
        assert_eq!(ErrorCode::InvalidMac, ErrorCode::InvalidMac);
    }

    #[test]
    fn display() {
        assert_eq!(format!("{}", ErrorCode::Ok), "everything is ok");
        assert_eq!(format!("{}", ErrorCode::Error), "general error");
        assert_eq!(
            format!("{}", ErrorCode::InvalidLength),
            "encrypted data is shorter than 156 bytes"
        );
        assert_eq!(
            format!("{}", ErrorCode::InvalidMagicNumber),
            "invalid magic number"
        );
        assert_eq!(
            format!("{}", ErrorCode::UnknownVersion),
            "unknown version number"
        );
        assert_eq!(
            format!("{}", ErrorCode::InvalidArgon2Params),
            "invalid Argon2 parameters"
        );
        assert_eq!(
            format!("{}", ErrorCode::InvalidArgon2Context),
            "invalid Argon2 context"
        );
        assert_eq!(
            format!("{}", ErrorCode::InvalidHeaderMac),
            "invalid header MAC"
        );
        assert_eq!(
            format!("{}", ErrorCode::InvalidMac),
            "invalid ciphertext MAC"
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn error_message() {
        {
            let expected = CString::new("everything is ok").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(ErrorCode::Ok, NonNull::new(buf.as_mut_ptr()), buf.len())
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("general error").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(ErrorCode::Error, NonNull::new(buf.as_mut_ptr()), buf.len())
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("encrypted data is shorter than 156 bytes").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::InvalidLength,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("invalid magic number").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::InvalidMagicNumber,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("unknown version number").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::UnknownVersion,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("invalid Argon2 parameters").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::InvalidArgon2Params,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("invalid Argon2 context").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::InvalidArgon2Context,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("invalid header MAC").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::InvalidHeaderMac,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }

        {
            let expected = CString::new("invalid ciphertext MAC").unwrap();
            let expected = expected.as_bytes_with_nul();
            let mut buf = vec![u8::default(); expected.len()];
            let code = unsafe {
                abcrypt_error_message(
                    ErrorCode::InvalidMac,
                    NonNull::new(buf.as_mut_ptr()),
                    buf.len(),
                )
            };
            assert_eq!(code, ErrorCode::Ok);
            assert_eq!(buf, expected);
        }
    }

    #[test]
    fn error_message_out_len() {
        assert_eq!(abcrypt_error_message_out_len(ErrorCode::Ok), 17);
        assert_eq!(abcrypt_error_message_out_len(ErrorCode::Error), 14);
        assert_eq!(abcrypt_error_message_out_len(ErrorCode::InvalidLength), 41);
        assert_eq!(
            abcrypt_error_message_out_len(ErrorCode::InvalidMagicNumber),
            21
        );
        assert_eq!(abcrypt_error_message_out_len(ErrorCode::UnknownVersion), 23);
        assert_eq!(
            abcrypt_error_message_out_len(ErrorCode::InvalidArgon2Params),
            26
        );
        assert_eq!(
            abcrypt_error_message_out_len(ErrorCode::InvalidArgon2Context),
            23
        );
        assert_eq!(
            abcrypt_error_message_out_len(ErrorCode::InvalidHeaderMac),
            19
        );
        assert_eq!(abcrypt_error_message_out_len(ErrorCode::InvalidMac), 23);
    }

    #[test]
    fn from_error_to_code() {
        assert_eq!(
            ErrorCode::from(Error::InvalidLength),
            ErrorCode::InvalidLength
        );
        assert_eq!(
            ErrorCode::from(Error::InvalidMagicNumber),
            ErrorCode::InvalidMagicNumber
        );
        assert_eq!(
            ErrorCode::from(Error::UnknownVersion(u8::MAX)),
            ErrorCode::UnknownVersion
        );
        assert_eq!(
            ErrorCode::from(Error::InvalidArgon2Params(
                abcrypt::argon2::Error::AdTooLong
            )),
            ErrorCode::InvalidArgon2Params
        );
        assert_eq!(
            ErrorCode::from(Error::InvalidArgon2Context(
                abcrypt::argon2::Error::AdTooLong
            )),
            ErrorCode::InvalidArgon2Context
        );
        assert_eq!(
            ErrorCode::from(Error::InvalidHeaderMac(abcrypt::blake2::digest::MacError)),
            ErrorCode::InvalidHeaderMac
        );
        assert_eq!(
            ErrorCode::from(Error::InvalidMac(abcrypt::chacha20poly1305::Error)),
            ErrorCode::InvalidMac
        );
    }
}
