// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The Argon2 parameters.

use wasm_bindgen::{prelude::wasm_bindgen, JsError};

/// The Argon2 parameters used for the encrypted data.
#[derive(Clone, Copy, Debug)]
#[wasm_bindgen]
pub struct Params(abcrypt::Params);

#[wasm_bindgen]
impl Params {
    /// Creates a new instance of the Argon2 parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns an error if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 164 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unsupported abcrypt version number.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 type is invalid.
    /// - The Argon2 version is invalid.
    /// - The Argon2 parameters are invalid.
    #[inline]
    #[wasm_bindgen(constructor)]
    pub fn new(ciphertext: &[u8]) -> Result<Self, JsError> {
        abcrypt::Params::new(ciphertext)
            .map(Self)
            .map_err(JsError::from)
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets memory size in KiB.
    #[must_use]
    #[inline]
    #[wasm_bindgen(js_name = memoryCost, getter)]
    pub fn memory_cost(&self) -> u32 {
        self.0.memory_cost()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets number of iterations.
    #[must_use]
    #[inline]
    #[wasm_bindgen(js_name = timeCost, getter)]
    pub fn time_cost(&self) -> u32 {
        self.0.time_cost()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets degree of parallelism.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn parallelism(&self) -> u32 {
        self.0.parallelism()
    }
}
