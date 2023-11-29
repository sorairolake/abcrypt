// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of decrypting a file from the abcrypt encrypted data format.

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

    use abcrypt::{Decryptor, Error};
    use anyhow::Context;
    use clap::Parser;
    use dialoguer::{theme::ColorfulTheme, Password};

    let opt = Opt::parse();

    let ciphertext = fs::read(&opt.input)
        .with_context(|| format!("could not read data from {}", opt.input.display()))?;

    let passphrase = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .interact()
        .context("could not read passphrase")?;
    let cipher = match Decryptor::new(&ciphertext, passphrase) {
        c @ Err(Error::InvalidHeaderMac(_)) => c.context("passphrase is incorrect"),
        c => c.context("the header in the encrypted data is invalid"),
    }?;
    let plaintext = cipher
        .decrypt_to_vec()
        .context("the encrypted data is corrupted")?;

    io::stdout()
        .write_all(&plaintext)
        .context("could not write data to stdout")?;
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
