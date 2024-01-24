// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Decrypts from the abcrypt encrypted data format.

use wasm_bindgen::{prelude::wasm_bindgen, JsError};

/// Decrypts `ciphertext` and into a newly allocated `Uint8Array`.
///
/// # Errors
///
/// Returns [`Err`] if any of the following are true:
///
/// - `ciphertext` is shorter than 156 bytes.
/// - The magic number is invalid.
/// - The version number is the unrecognized abcrypt version number.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
/// - The MAC (authentication tag) of the header is invalid.
/// - The MAC (authentication tag) of the ciphertext is invalid.
#[wasm_bindgen]
pub fn decrypt(ciphertext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsError> {
    abcrypt::decrypt(ciphertext, passphrase).map_err(JsError::from)
}
