// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context;

/// Gets the encryption parameters.
pub fn get(data: &[u8]) -> anyhow::Result<abcrypt::Params> {
    abcrypt::Params::new(data).context("data is not a valid abcrypt encrypted file")
}

/// Prints the encryption parameters.
fn display(m_cost: u32, t_cost: u32, p_cost: u32) {
    eprint!("Parameters used: m_cost = {m_cost}; t_cost = {t_cost}; p_cost = {p_cost};");
}

/// Prints the encryption parameters with a newline.
pub fn displayln(m_cost: u32, t_cost: u32, p_cost: u32) {
    display(m_cost, t_cost, p_cost);
    eprintln!();
}

/// The abcrypt parameters used for the encrypted data.
#[cfg(feature = "json")]
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct Params {
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

#[cfg(feature = "json")]
impl Params {
    /// Creates a new `Params`.
    pub const fn new(params: &abcrypt::Params) -> Self {
        let (m_cost, t_cost, p_cost) = (params.m_cost(), params.t_cost(), params.p_cost());
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Serializes the given data structure.
    pub fn to_vec(self) -> anyhow::Result<Vec<u8>> {
        serde_json::to_vec(&self).context("could not serialize as JSON")
    }
}
