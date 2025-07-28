// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `abcrypt-wasm` crate is the Wasm bindings for the `abcrypt` crate.

#![doc(html_root_url = "https://docs.rs/abcrypt-wasm/0.5.0/")]
// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod decrypt;
mod encrypt;
mod params;

use wasm_bindgen::prelude::wasm_bindgen;

pub use crate::{
    decrypt::decrypt,
    encrypt::{encrypt, encrypt_with_context, encrypt_with_params},
    params::Params,
};

#[allow(clippy::missing_const_for_fn)]
/// Returns the number of bytes of the header.
#[must_use]
#[wasm_bindgen(js_name = headerSize)]
pub fn header_size() -> usize {
    abcrypt::HEADER_SIZE
}

#[allow(clippy::missing_const_for_fn)]
/// Returns the number of bytes of the MAC (authentication tag) of the
/// ciphertext.
#[must_use]
#[wasm_bindgen(js_name = tagSize)]
pub fn tag_size() -> usize {
    abcrypt::TAG_SIZE
}

#[cfg(test)]
mod tests {
    use wasm_bindgen_test::wasm_bindgen_test;

    #[wasm_bindgen_test]
    fn header_size() {
        assert_eq!(super::header_size(), 148);
        assert_eq!(super::header_size(), abcrypt::HEADER_SIZE);
    }

    #[wasm_bindgen_test]
    fn tag_size() {
        assert_eq!(super::tag_size(), 16);
        assert_eq!(super::tag_size(), abcrypt::TAG_SIZE);
    }
}
