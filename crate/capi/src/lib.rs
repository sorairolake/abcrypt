// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt-capi` crate is the C API for the [`abcrypt`] crate.

#![doc(html_root_url = "https://docs.rs/abcrypt-capi/0.1.0/")]
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
    error::ErrorCode,
    params::Params,
};
