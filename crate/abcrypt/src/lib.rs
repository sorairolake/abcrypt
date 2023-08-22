// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `scryptenc` crate is an implementation of the scrypt encrypted data
//! format.
//!
//! The format is defined [here][specification-url].
//!
//! # Examples
//!
//! ## Encrypt and decrypt
//!
//! ```
//! use scryptenc::{scrypt::Params, Decryptor, Encryptor};
//!
//! let data = b"Hello, world!";
//! let password = "password";
//!
//! // Encrypt `data` using `password`.
//! let params = Params::new(10, 8, 1, Params::RECOMMENDED_LEN).unwrap();
//! let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
//! assert_ne!(encrypted, data);
//!
//! // And decrypt it back.
//! let decrypted = Decryptor::new(encrypted, password)
//!     .and_then(Decryptor::decrypt_to_vec)
//!     .unwrap();
//! assert_eq!(decrypted, data);
//! ```
//!
//! ## Extract the scrypt parameters in the encrypted data
//!
//! ```
//! use scryptenc::{scrypt, Encryptor};
//!
//! let data = b"Hello, world!";
//! let password = "password";
//!
//! // Encrypt `data` using `password`.
//! let params = scrypt::Params::new(10, 8, 1, scrypt::Params::RECOMMENDED_LEN).unwrap();
//! let encrypted = Encryptor::with_params(data, password, params).encrypt_to_vec();
//!
//! // And extract the scrypt parameters from it.
//! let params = scryptenc::Params::new(encrypted).unwrap();
//! assert_eq!(params.log_n(), 10);
//! assert_eq!(params.n(), 1024);
//! assert_eq!(params.r(), 8);
//! assert_eq!(params.p(), 1);
//! ```
//!
//! [specification-url]: https://github.com/Tarsnap/scrypt/blob/1.3.1/FORMAT

#![doc(html_root_url = "https://docs.rs/scryptenc/0.7.1/")]
#![no_std]
#![cfg_attr(doc_cfg, feature(doc_auto_cfg, doc_cfg))]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod decrypt;
mod encrypt;
mod error;
mod format;
mod params;

pub use hmac::digest;
pub use scrypt;

pub use crate::{decrypt::Decryptor, encrypt::Encryptor, error::Error, params::Params};
