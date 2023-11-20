// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt` crate is an implementation of the [abcrypt encrypted data
//! format].
//!
//! This crate implements version 0 of the format.
//!
//! # Examples
//!
//! ## Encryption and decryption
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use abcrypt::{argon2::Params, Decryptor, Encryptor};
//!
//! let data = b"Hello, world!\n";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = Params::new(32, 3, 4, None).unwrap();
//! let ciphertext = Encryptor::with_params(data, passphrase, params)
//!     .map(|c| c.encrypt_to_vec())
//!     .unwrap();
//! assert_ne!(ciphertext, data);
//!
//! // And decrypt it back.
//! let plaintext = Decryptor::new(&ciphertext, passphrase)
//!     .and_then(|c| c.decrypt_to_vec())
//!     .unwrap();
//! assert_eq!(plaintext, data);
//! # }
//! ```
//!
//! ### `no_std` support
//!
//! This crate supports `no_std` mode and can be used without the `alloc` crate
//! and the `std` crate. Disables the `default` feature to enable this.
//!
//! Note that the memory blocks used by Argon2 when calculating a derived key is
//! limited to 256 KiB when the `alloc` feature is disabled.
//!
//! ```
//! use abcrypt::{argon2::Params, Decryptor, Encryptor};
//!
//! let data = b"Hello, world!\n";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = Params::new(32, 3, 4, None).unwrap();
//! let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
//! let mut buf = [u8::default(); 170];
//! cipher.encrypt(&mut buf);
//! assert_ne!(buf, data.as_slice());
//!
//! // And decrypt it back.
//! let cipher = Decryptor::new(&buf, passphrase).unwrap();
//! let mut buf = [u8::default(); 14];
//! cipher.decrypt(&mut buf).unwrap();
//! assert_eq!(buf, data.as_slice());
//! ```
//!
//! ## Extracting the Argon2 parameters in the encrypted data
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use abcrypt::{argon2, Encryptor};
//!
//! let data = b"Hello, world!\n";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let ciphertext = Encryptor::new(data, passphrase)
//!     .map(|c| c.encrypt_to_vec())
//!     .unwrap();
//!
//! // And extract the Argon2 parameters from it.
//! let params = abcrypt::Params::new(ciphertext).unwrap();
//! assert_eq!(params.m_cost(), argon2::Params::DEFAULT_M_COST);
//! assert_eq!(params.t_cost(), argon2::Params::DEFAULT_T_COST);
//! assert_eq!(params.p_cost(), argon2::Params::DEFAULT_P_COST);
//! # }
//! ```
//!
//! [abcrypt encrypted data format]: https://sorairolake.github.io/abcrypt/book/format.html

#![doc(html_root_url = "https://docs.rs/abcrypt/0.2.6/")]
#![no_std]
#![cfg_attr(doc_cfg, feature(doc_auto_cfg, doc_cfg))]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[cfg(feature = "alloc")]
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
    decrypt::Decryptor,
    encrypt::Encryptor,
    error::{Error, Result},
    format::{HEADER_SIZE, TAG_SIZE},
    params::Params,
};

#[cfg(feature = "alloc")]
pub use crate::{
    decrypt::decrypt,
    encrypt::{encrypt, encrypt_with_params},
};

const ARGON2_ALGORITHM: argon2::Algorithm = argon2::Algorithm::Argon2id;
const ARGON2_VERSION: argon2::Version = argon2::Version::V0x13;

#[cfg(not(feature = "alloc"))]
// 1 MiB.
const MEMORY_BLOCKS: [argon2::Block; usize::pow(2, 8)] = [argon2::Block::new(); usize::pow(2, 8)];

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "alloc"))]
    use super::*;

    #[cfg(not(feature = "alloc"))]
    #[test]
    fn memory_blocks() {
        assert_eq!(MEMORY_BLOCKS.len(), usize::pow(2, 8));
    }
}
