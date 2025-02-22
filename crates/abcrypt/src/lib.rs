// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt` crate is an implementation of the [abcrypt encrypted data
//! format].
//!
//! This crate supports version 1 of the abcrypt format.
//!
//! # Examples
//!
//! ## Encryption and decryption
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use abcrypt::{Decryptor, Encryptor, argon2::Params};
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
//! use abcrypt::{
//!     Argon2, Decryptor, Encryptor,
//!     argon2::{Algorithm, Params, Version},
//! };
//!
//! let data = b"Hello, world!\n";
//! let passphrase = "passphrase";
//!
//! // Encrypt `data` using `passphrase`.
//! let params = Params::new(32, 3, 4, None).unwrap();
//! let cipher = Encryptor::with_params(data, passphrase, params).unwrap();
//! let mut buf = [u8::default(); 178];
//! cipher.encrypt(&mut buf);
//! assert_ne!(buf.as_slice(), data);
//!
//! let argon2 = Argon2::new(buf).unwrap();
//! assert_eq!(argon2.variant(), Algorithm::Argon2id);
//! assert_eq!(argon2.version(), Version::V0x13);
//!
//! // And decrypt it back.
//! let cipher = Decryptor::new(&buf, passphrase).unwrap();
//! let mut buf = [u8::default(); 14];
//! cipher.decrypt(&mut buf).unwrap();
//! assert_eq!(buf, *data);
//! ```
//!
//! ## Extracting the Argon2 parameters in the encrypted data
//!
//! ```
//! # #[cfg(feature = "alloc")]
//! # {
//! use abcrypt::{Encryptor, argon2};
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
//! assert_eq!(params.memory_cost(), argon2::Params::DEFAULT_M_COST);
//! assert_eq!(params.time_cost(), argon2::Params::DEFAULT_T_COST);
//! assert_eq!(params.parallelism(), argon2::Params::DEFAULT_P_COST);
//! # }
//! ```
//!
//! [abcrypt encrypted data format]: https://sorairolake.github.io/abcrypt/book/format.html

#![doc(html_root_url = "https://docs.rs/abcrypt/0.4.0/")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

#[cfg(feature = "alloc")]
#[macro_use]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

mod argon2_context;
mod decrypt;
mod encrypt;
mod error;
mod format;
mod params;

pub use argon2;
pub use blake2;
pub use chacha20poly1305;

pub use crate::{
    argon2_context::Argon2,
    decrypt::Decryptor,
    encrypt::Encryptor,
    error::{Error, Result},
    format::{HEADER_SIZE, TAG_SIZE},
    params::Params,
};
#[cfg(feature = "alloc")]
pub use crate::{
    decrypt::decrypt,
    encrypt::{encrypt, encrypt_with_context, encrypt_with_params},
};

#[cfg(not(feature = "alloc"))]
// 1 MiB.
const MEMORY_BLOCKS: [argon2::Block; usize::pow(2, 8)] = [argon2::Block::new(); usize::pow(2, 8)];

const AAD: &[u8] = &[];

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
