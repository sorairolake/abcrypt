// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]
#![allow(clippy::multiple_crate_versions)]

mod app;
mod cli;
mod input;
mod output;
mod params;
mod password;
mod utils;

use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match app::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err:?}");
            #[allow(clippy::option_if_let_else)]
            if let Some(e) = err.downcast_ref::<io::Error>() {
                sysexits::ExitCode::from(e.kind()).into()
            } else if err.is::<abcrypt::Error>() {
                sysexits::ExitCode::DataErr.into()
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
