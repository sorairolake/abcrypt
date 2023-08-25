// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of reading the Argon2 parameters from a file.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[cfg(feature = "std")]
use anyhow::Context;
#[cfg(feature = "std")]
use clap::Parser;

#[cfg(feature = "std")]
#[derive(Debug, Parser)]
#[clap(version, about)]
struct Opt {
    /// File to print the Argon2 parameters.
    #[clap(value_name("FILE"))]
    input: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let contents = std::fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let params = abcrypt::Params::new(contents).with_context(|| {
        format!(
            "{} is not a valid Argon2 encrypted file",
            opt.input.display()
        )
    })?;
    println!(
        "Parameters used: m = {}; t = {}; p = {};",
        params.m_cost(),
        params.t_cost(),
        params.p_cost()
    );
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
