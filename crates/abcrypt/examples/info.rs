// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! An example of reading the Argon2 parameters from a file.

use std::{
    fs,
    io::{self, Read},
    path::PathBuf,
};

use abcrypt::Params;
use anyhow::Context;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    /// Output the encryption parameters as JSON.
    #[arg(short, long)]
    json: bool,

    /// Input file.
    ///
    /// If [FILE] is not specified, data will be read from standard input.
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
            .context("could not read data from standard input")?;
        Ok(buf)
    }?;

    let params = Params::new(ciphertext).context("data is not a valid abcrypt encrypted file")?;
    if opt.json {
        let output = serde_json::to_string(&params).context("could not serialize as JSON")?;
        println!("{output}");
    } else {
        println!(
            "Parameters used: memoryCost = {}; timeCost = {}; parallelism = {};",
            params.memory_cost(),
            params.time_cost(),
            params.parallelism()
        );
    }
    Ok(())
}
