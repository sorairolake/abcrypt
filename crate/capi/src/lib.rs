// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt-capi` crate is the C API for the [`abcrypt`] crate.

#![doc(html_root_url = "https://docs.rs/abcrypt-capi/0.1.2/")]
#![cfg_attr(doc_cfg, feature(doc_auto_cfg, doc_cfg))]
// Lint levels of rustc.
#![deny(missing_debug_implementations, missing_docs)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

mod decrypt;
mod encrypt;
mod error;
mod params;

pub use crate::{
    decrypt::abcrypt_decrypt,
    encrypt::{abcrypt_encrypt, abcrypt_encrypt_with_params},
    error::{abcrypt_error_message, abcrypt_error_message_out_len, ErrorCode},
    params::{
        abcrypt_params_free, abcrypt_params_m_cost, abcrypt_params_new, abcrypt_params_p_cost,
        abcrypt_params_read, abcrypt_params_t_cost, Params,
    },
};

/// The number of bytes of the header.
pub const HEADER_SIZE: usize = 140;

/// The number of bytes of the MAC (authentication tag) of the ciphertext.
pub const TAG_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size() {
        assert_eq!(HEADER_SIZE, 140);
        assert_eq!(HEADER_SIZE, abcrypt::HEADER_SIZE);
    }

    #[test]
    fn tag_size() {
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(TAG_SIZE, abcrypt::TAG_SIZE);
    }
}
