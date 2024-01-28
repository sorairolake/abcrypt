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
    #[allow(clippy::use_self)]
    /// Creates a new instance of the Argon2 parameters from `ciphertext`.
    ///
    /// # Errors
    ///
    /// Returns [`Err`] if any of the following are true:
    ///
    /// - `ciphertext` is shorter than 156 bytes.
    /// - The magic number is invalid.
    /// - The version number is the unrecognized abcrypt version number.
    /// - The Argon2 parameters are invalid.
    #[wasm_bindgen(constructor)]
    pub fn new(ciphertext: &[u8]) -> Result<Params, JsError> {
        abcrypt::Params::new(ciphertext)
            .map(Self)
            .map_err(JsError::from)
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets memory size in KiB.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn m_cost(&self) -> u32 {
        self.0.m_cost()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets number of iterations.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn t_cost(&self) -> u32 {
        self.0.t_cost()
    }

    #[allow(clippy::missing_const_for_fn)]
    /// Gets degree of parallelism.
    #[must_use]
    #[inline]
    #[wasm_bindgen(getter)]
    pub fn p_cost(&self) -> u32 {
        self.0.p_cost()
    }
}
