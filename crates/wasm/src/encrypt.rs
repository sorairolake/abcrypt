// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Encrypts to the abcrypt encrypted data format.

use abcrypt::{
    Error,
    argon2::{Algorithm, Params},
};
use wasm_bindgen::{JsError, prelude::wasm_bindgen};

/// Encrypts `plaintext` and into a newly allocated `Uint8Array`.
///
/// This uses the recommended Argon2 parameters according to the OWASP Password
/// Storage Cheat Sheet. This also uses Argon2id as the Argon2 type and version
/// 0x13 as the Argon2 version.
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
/// This uses Argon2id as the Argon2 type and version 0x13 as the Argon2
/// version.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
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

#[allow(clippy::module_name_repetitions)]
/// Encrypts `plaintext` with the specified Argon2 type, Argon2 version and
/// Argon2 parameters and into a newly allocated `Uint8Array`.
///
/// # Errors
///
/// Returns an error if any of the following are true:
///
/// - The Argon2 type is invalid.
/// - The Argon2 version is invalid.
/// - The Argon2 parameters are invalid.
/// - The Argon2 context is invalid.
#[wasm_bindgen(js_name = encryptWithContext)]
pub fn encrypt_with_context(
    plaintext: &[u8],
    passphrase: &[u8],
    argon2_type: u32,
    argon2_version: u32,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<Vec<u8>, JsError> {
    let argon2_type = match argon2_type {
        0 => Ok(Algorithm::Argon2d),
        1 => Ok(Algorithm::Argon2i),
        2 => Ok(Algorithm::Argon2id),
        t => Err(Error::InvalidArgon2Type(t)),
    }?;
    let argon2_version = argon2_version.try_into()?;
    let params = Params::new(memory_cost, time_cost, parallelism, None)?;
    abcrypt::encrypt_with_context(plaintext, passphrase, argon2_type, argon2_version, params)
        .map_err(JsError::from)
}
