// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use anyhow::Context;

/// Reads the data to process.
pub fn read(path: Option<&Path>) -> anyhow::Result<Vec<u8>> {
    if let Some(p) = path {
        fs::read(p).with_context(|| format!("could not read data from {}", p.display()))
    } else {
        let mut buf = Vec::new();
        io::stdin()
            .read_to_end(&mut buf)
            .context("could not read data from stdin")?;
        Ok(buf)
    }
}
