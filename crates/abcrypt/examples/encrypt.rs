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

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use abcrypt::argon2::Params;
use anyhow::Context;
use clap::Parser;
use dialoguer::{theme::ColorfulTheme, Password};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"))]
    output: Option<PathBuf>,

    /// Set the memory size in KiB.
    #[arg(short, long, default_value("19456"), value_name("NUM"))]
    memory_cost: u32,

    /// Set the number of iterations.
    #[arg(short, long, default_value("2"), value_name("NUM"))]
    time_cost: u32,

    /// Set the degree of parallelism.
    #[arg(short, long, default_value("1"), value_name("NUM"))]
    parallelism: u32,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from standard input.
    #[arg(value_name("FILE"))]
    input: Option<PathBuf>,
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    let plaintext = if let Some(file) = opt.input {
        fs::read(&file).with_context(|| format!("could not read data from {}", file.display()))
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("could not read data from standard input")?;
        Ok(buf)
    }?;

    let passphrase = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .with_confirmation("Confirm passphrase", "Passphrases mismatch, try again")
        .interact()
        .context("could not read passphrase")?;
    let params = Params::new(opt.memory_cost, opt.time_cost, opt.parallelism, None)?;
    let ciphertext = abcrypt::encrypt_with_params(plaintext, passphrase, params)?;

    if let Some(file) = opt.output {
        fs::write(&file, ciphertext)
            .with_context(|| format!("could not write data to {}", file.display()))
    } else {
        io::stdout()
            .write_all(&ciphertext)
            .context("could not write data to standard output")
    }
}
