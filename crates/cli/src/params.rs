// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use anyhow::Context;

/// Gets the encryption parameters.
pub fn get(data: &[u8]) -> anyhow::Result<abcrypt::Params> {
    abcrypt::Params::new(data).context("data is not a valid abcrypt encrypted file")
}

/// Prints the encryption parameters.
fn display(memory_cost: u32, time_cost: u32, parallelism: u32) {
    eprint!("Parameters used: memoryCost = {memory_cost}; timeCost = {time_cost}; parallelism = {parallelism};");
}

/// Prints the encryption parameters with a newline.
pub fn displayln(memory_cost: u32, time_cost: u32, parallelism: u32) {
    display(memory_cost, time_cost, parallelism);
    eprintln!();
}
