// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of encrypting a file to the abcrypt encrypted data format.

use std::{
    fs,
    io::{self, Read, Write},
    path::PathBuf,
};

use abcrypt::argon2::{Algorithm, Params, Version};
use anyhow::Context;
use clap::{Parser, ValueEnum};
use dialoguer::{theme::ColorfulTheme, Password};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Output the result to a file.
    #[arg(short, long, value_name("FILE"))]
    output: Option<PathBuf>,

    /// Set the Argon2 type.
    #[arg(
        long,
        value_enum,
        default_value_t,
        value_name("TYPE"),
        ignore_case(true)
    )]
    argon2_type: Argon2Type,

    /// Set the Argon2 version.
    #[arg(
        long,
        value_enum,
        default_value_t,
        value_name("VERSION"),
        ignore_case(true)
    )]
    argon2_version: Argon2Version,

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

#[derive(Clone, Debug, Default, ValueEnum)]
enum Argon2Type {
    /// Argon2d.
    Argon2d,

    /// Argon2i.
    Argon2i,

    /// Argon2id.
    #[default]
    Argon2id,
}

impl From<Argon2Type> for Algorithm {
    fn from(argon2_type: Argon2Type) -> Self {
        match argon2_type {
            Argon2Type::Argon2d => Self::Argon2d,
            Argon2Type::Argon2i => Self::Argon2i,
            Argon2Type::Argon2id => Self::Argon2id,
        }
    }
}

#[derive(Clone, Debug, Default, ValueEnum)]
enum Argon2Version {
    /// Version 0x10.
    #[value(name = "0x10", alias("16"))]
    V0x10,

    /// Version 0x13.
    #[default]
    #[value(name = "0x13", alias("19"))]
    V0x13,
}

impl From<Argon2Version> for Version {
    fn from(argon2_version: Argon2Version) -> Self {
        match argon2_version {
            Argon2Version::V0x10 => Self::V0x10,
            Argon2Version::V0x13 => Self::V0x13,
        }
    }
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
    let ciphertext = abcrypt::encrypt_with_context(
        plaintext,
        passphrase,
        opt.argon2_type.into(),
        opt.argon2_version.into(),
        params,
    )?;

    if let Some(file) = opt.output {
        fs::write(&file, ciphertext)
            .with_context(|| format!("could not write data to {}", file.display()))
    } else {
        io::stdout()
            .write_all(&ciphertext)
            .context("could not write data to standard output")
    }
}
