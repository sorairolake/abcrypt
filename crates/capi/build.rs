// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
    env, fs, io,
    path::Path,
    process::{Command, ExitStatus},
};

fn generate_man_page(out_dir: &str) -> io::Result<ExitStatus> {
    let man_dir = env::current_dir()?.join("docs/man/man3");
    let mut command = Command::new("asciidoctor");
    command
        .args(["-b", "manpage"])
        .args(["-D", out_dir])
        .arg(man_dir.join("*.3.adoc"))
        .status()
}

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

    println!("cargo:rerun-if-changed=docs/man");

    let out_dir = env::var("OUT_DIR").expect("environment variable `OUT_DIR` not defined");
    match generate_man_page(&out_dir) {
        Ok(exit_status) => {
            if !exit_status.success() {
                println!("cargo:warning=Asciidoctor failed: {exit_status}");
            }
        }
        Err(err) => {
            println!("cargo:warning=failed to execute Asciidoctor: {err}");
        }
    }
}
