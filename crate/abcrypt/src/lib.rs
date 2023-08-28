// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt` crate is an implementation of the abcrypt encrypted data
//! format.
//!
//! # Examples
//!
//! ## Encrypt and decrypt
//!
//! ```
//! use abcrypt::{argon2::Params, Decryptor, Encryptor};
//!
//! let data = b"Hello, world!";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = Params::new(32, 3, 4, None).unwrap();
//! let ciphertext = Encryptor::with_params(data, passphrase, params)
//!     .map(Encryptor::encrypt_to_vec)
//!     .unwrap();
//! assert_ne!(ciphertext, data);
//!
//! // And decrypt it back.
//! let plaintext = Decryptor::new(ciphertext, passphrase)
//!     .and_then(Decryptor::decrypt_to_vec)
//!     .unwrap();
//! assert_eq!(plaintext, data);
//! ```
//!
//! ## Extract the Argon2 parameters in the encrypted data
//!
//! ```
//! use abcrypt::{argon2, Encryptor};
//!
//! let data = b"Hello, world!";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = argon2::Params::new(32, 3, 4, None).unwrap();
//! let ciphertext = Encryptor::with_params(data, passphrase, params)
//!     .map(Encryptor::encrypt_to_vec)
//!     .unwrap();
//!
//! // And extract the Argon2 parameters from it.
//! let params = abcrypt::Params::new(ciphertext).unwrap();
//! assert_eq!(params.m_cost(), 32);
//! assert_eq!(params.t_cost(), 3);
//! assert_eq!(params.p_cost(), 4);
//! ```

#![doc(html_root_url = "https://docs.rs/abcrypt/0.1.0/")]
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

pub use argon2;
pub use blake2;
pub use chacha20poly1305;

pub use crate::{
    decrypt::{decrypt, Decryptor},
    encrypt::{encrypt, encrypt_with_params, Encryptor},
    error::{Error, Result},
    params::Params,
};

const ARGON2_ALGORITHM: argon2::Algorithm = argon2::Algorithm::Argon2id;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;
