// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of decrypting a file from the scrypt encrypted data format.

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
    /// File to decrypt.
    #[clap(value_name("INFILE"))]
    input: std::path::PathBuf,

    /// File to write the result to.
    #[clap(value_name("OUTFILE"))]
    output: std::path::PathBuf,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let ciphertext = std::fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let password = dialoguer::Password::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Enter password")
        .interact()
        .context("could not read password")?;
    let cipher = match scryptenc::Decryptor::new(ciphertext, password) {
        c @ Err(scryptenc::Error::InvalidHeaderMac(_)) => c.context("password is incorrect"),
        c => c.with_context(|| format!("the header in {} is invalid", opt.input.display())),
    }?;
    let decrypted = cipher
        .decrypt_to_vec()
        .with_context(|| format!("{} is corrupted", opt.input.display()))?;
    std::fs::write(opt.output, decrypted)
        .with_context(|| format!("could not write the result to {}", opt.input.display()))?;
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
