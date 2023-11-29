// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use std::{fs, path::Path};

fn main() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    cbindgen::generate(crate_dir)
        .expect("failed to generate bindings")
        .write_to_file("include/abcrypt.h");

    let lock_file = crate_dir.join("Cargo.lock");
    if lock_file.exists() {
        fs::remove_file(lock_file)
            .unwrap_or_else(|err| println!("cargo:warning=failed to remove `Cargo.lock`: {err}"));
    }
}
