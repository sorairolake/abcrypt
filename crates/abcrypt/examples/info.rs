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
#[derive(Debug, clap::Parser)]
#[command(version, about)]
struct Opt {
    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from stdin.
    #[arg(value_name("FILE"))]
    input: Option<std::path::PathBuf>,
}

#[cfg(feature = "std")]
fn main() -> anyhow::Result<()> {
    use std::{
        fs,
        io::{self, Read},
    };

    use abcrypt::Params;
    use anyhow::Context;
    use clap::Parser;

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

    let params = Params::new(ciphertext).context("data is not a valid abcrypt encrypted file")?;
    println!(
        "Parameters used: memoryCost = {}; timeCost = {}; parallelism = {};",
        params.memory_cost(),
        params.time_cost(),
        params.parallelism()
    );
    Ok(())
}

#[cfg(not(feature = "std"))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("`std` feature is required");
}
