// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Error types for this crate.

use pyo3::{PyErr, exceptions::PyValueError};

/// The error type for the abcrypt encrypted data format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(abcrypt::Error);

impl From<Error> for PyErr {
    #[inline]
    fn from(err: Error) -> Self {
        PyValueError::new_err(err.0.to_string())
    }
}

impl From<abcrypt::Error> for Error {
    #[inline]
    fn from(err: abcrypt::Error) -> Self {
        Self(err)
    }
}
