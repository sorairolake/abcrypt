// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

use anyhow::Context;

/// Writes the result to a file.
pub fn write_to_file(path: &Path, data: &[u8]) -> anyhow::Result<()> {
    fs::write(path, data).with_context(|| format!("could not write data to {}", path.display()))
}

/// Writes the result to stdout.
pub fn write_to_stdout(data: &[u8]) -> anyhow::Result<()> {
    io::stdout()
        .write_all(data)
        .context("could not write data to stdout")
}
