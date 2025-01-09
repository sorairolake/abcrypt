// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Lint levels of rustc.
#![forbid(unsafe_code)]
// Lint levels of Clippy.
#![allow(clippy::multiple_crate_versions)]

mod app;
mod cli;
mod input;
mod output;
mod params;
mod passphrase;
mod utils;

use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match app::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:?}");
            if let Some(e) = err.downcast_ref::<io::Error>() {
                return sysexits::ExitCode::from(e.kind()).into();
            }
            if err.is::<abcrypt::Error>() {
                return sysexits::ExitCode::DataErr.into();
            }
            ExitCode::FAILURE
        }
    }
}
