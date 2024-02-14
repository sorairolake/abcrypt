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

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use abcrypt::{Decryptor, Error};
use anyhow::Context;
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Password};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"))]
    output: Option<PathBuf>,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from stdin.
    #[arg(value_name("FILE"))]
    input: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let ciphertext = if let Some(file) = opt.input {
        fs::read(&file).with_context(|| format!("could not read data from {}", file.display()))
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("could not read data from stdin")?;
        Ok(buf)
    }?;

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

    if let Some(file) = opt.output {
        fs::write(&file, plaintext)
            .with_context(|| format!("could not write data to {}", file.display()))
    } else {
        io::stdout()
            .write_all(&plaintext)
            .context("could not write data to stdout")
    }
}
