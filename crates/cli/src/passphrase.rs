// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    env,
    fs::File,
    io::{self, BufRead, BufReader},
    path::Path,
};

use anyhow::Context;
use dialoguer::{theme::ColorfulTheme, Password};

use crate::utils::StringExt;

/// Reads the passphrase from /dev/tty.
pub fn read_passphrase_from_tty() -> anyhow::Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .with_confirmation("Confirm passphrase", "Passphrases mismatch, try again")
        .allow_empty_password(true)
        .interact()
        .context("could not read passphrase")
}

/// Reads the passphrase from standard input.
pub fn read_passphrase_from_stdin() -> anyhow::Result<String> {
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("could not read passphrase from standard input")?;
    buf.remove_newline();
    Ok(buf)
}

/// Reads the passphrase from /dev/tty only once.
pub fn read_passphrase_from_tty_once() -> anyhow::Result<String> {
    Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter passphrase")
        .allow_empty_password(true)
        .interact()
        .context("could not read passphrase")
}

/// Reads the passphrase from the environment variable.
pub fn read_passphrase_from_env(key: &str) -> anyhow::Result<String> {
    env::var(key).context("could not read passphrase from environment variable")
}

/// Reads the passphrase from the file.
pub fn read_passphrase_from_file(path: &Path) -> anyhow::Result<String> {
    let file = File::open(path).with_context(|| format!("could not open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut buf = String::new();
    reader
        .read_line(&mut buf)
        .with_context(|| format!("could not read passphrase from {}", path.display()))?;
    buf.remove_newline();
    Ok(buf)
}
