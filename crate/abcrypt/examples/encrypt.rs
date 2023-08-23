// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of encrypting a file to the scrypt encrypted data format.

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
    /// Set the memory size in KiB.
    #[clap(short, long, default_value("4096"), value_name("NUM"))]
    memory_size: u32,

    /// Set the number of iterations.
    #[clap(short('t'), long, default_value("3"), value_name("NUM"))]
    iterations: u32,

    /// Set the degree of parallelism.
    #[clap(short, long, default_value("1"), value_name("NUM"))]
    parallelism: u32,

    /// File to encrypt.
    #[clap(value_name("INFILE"))]
    input: std::path::PathBuf,

    /// File to write the result to.
    #[clap(value_name("OUTFILE"))]
    output: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let plaintext = std::fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let password = dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Enter password")
        .with_confirmation("Confirm password", "Passwords mismatch, try again")
        .interact()
        .context("could not read password")?;
    let params =
        abcrypt::argon2::Params::new(opt.memory_size, opt.iterations, opt.parallelism, None)?;
    let cipher = abcrypt::Encryptor::with_params(plaintext, password, params)?;
    let ciphertext = cipher.encrypt_to_vec();
    std::fs::write(opt.output, ciphertext)
        .with_context(|| format!("could not write the result to {}", opt.input.display()))?;
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
