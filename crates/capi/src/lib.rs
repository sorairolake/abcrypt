// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt-capi` crate is the C API for the `abcrypt` crate.

#![doc(html_root_url = "https://docs.rs/abcrypt-capi/0.3.2/")]
// Lint levels of rustc.
#![deny(missing_docs)]

mod decrypt;
mod encrypt;
mod error;
mod params;

pub use crate::{
    decrypt::abcrypt_decrypt,
    encrypt::{abcrypt_encrypt, abcrypt_encrypt_with_context, abcrypt_encrypt_with_params},
    error::{abcrypt_error_message, abcrypt_error_message_out_len, ErrorCode},
    params::{
        abcrypt_params_free, abcrypt_params_memory_cost, abcrypt_params_new,
        abcrypt_params_parallelism, abcrypt_params_read, abcrypt_params_time_cost, Params,
    },
};

/// The number of bytes of the header.
pub const HEADER_SIZE: usize = 148;

/// The number of bytes of the MAC (authentication tag) of the ciphertext.
pub const TAG_SIZE: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_size() {
        assert_eq!(HEADER_SIZE, 148);
        assert_eq!(HEADER_SIZE, abcrypt::HEADER_SIZE);
    }

    #[test]
    fn tag_size() {
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(TAG_SIZE, abcrypt::TAG_SIZE);
    }
}
