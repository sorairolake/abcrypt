// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

use abcrypt::argon2::Params;
use wasm_bindgen::{prelude::wasm_bindgen, JsError};

/// Encrypts `plaintext` and into a newly allocated `Uint8Array`.
///
/// This uses the recommended Argon2 parameters.
///
/// # Errors
///
/// Returns an error if the Argon2 context is invalid.
#[wasm_bindgen]
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, JsError> {
    abcrypt::encrypt(plaintext, passphrase).map_err(JsError::from)
}

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified Argon2 parameters and into a newly
/// allocated `Uint8Array`.
///
/// # Errors
///
/// Returns an error if the Argon2 context is invalid.
#[wasm_bindgen(js_name = encryptWithParams)]
pub fn encrypt_with_params(
    plaintext: &[u8],
    passphrase: &[u8],
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Vec<u8>, JsError> {
    let params = Params::new(memory_cost, time_cost, parallelism, None)?;
    abcrypt::encrypt_with_params(plaintext, passphrase, params).map_err(JsError::from)
}
