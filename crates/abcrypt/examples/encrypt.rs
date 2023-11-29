// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of encrypting a file to the abcrypt encrypted data format.

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

#[cfg(feature = "std")]
#[derive(Debug, clap::Parser)]
#[command(version, about)]
struct Opt {
    /// Set the memory size in KiB.
    #[arg(short, long, default_value("19456"), value_name("NUM"))]
    memory_size: u32,

    /// Set the number of iterations.
    #[arg(short('t'), long, default_value("2"), value_name("NUM"))]
    iterations: u32,

    /// Set the degree of parallelism.
    #[arg(short, long, default_value("1"), value_name("NUM"))]
    parallelism: u32,

    /// Input file.
    #[arg(value_name("FILE"))]
    input: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    use std::{
        fs,
        io::{self, Write},
    };

    use abcrypt::argon2::Params;
    use anyhow::Context;
    use clap::Parser;
    use dialoguer::{theme::ColorfulTheme, Password};

    let opt = Opt::parse();

    let plaintext = fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let passphrase = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .with_confirmation("Confirm passphrase", "Passphrases mismatch, try again")
        .interact()
        .context("could not read passphrase")?;
    let params = Params::new(opt.memory_size, opt.iterations, opt.parallelism, None)?;
    let ciphertext = abcrypt::encrypt_with_params(plaintext, passphrase, params)?;

    io::stdout()
        .write_all(&ciphertext)
        .context("could not write data to stdout")?;
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
