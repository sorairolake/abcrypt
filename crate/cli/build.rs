// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

// Lint levels of rustc.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![warn(rust_2018_idioms)]
// Lint levels of Clippy.
#![warn(clippy::cargo, clippy::nursery, clippy::pedantic)]

use std::{
    env, io,
    path::Path,
    process::{Command, ExitStatus},
};

fn generate_man_page(out_dir: impl AsRef<Path>) -> io::Result<ExitStatus> {
    let man_dir = env::current_dir()?.join("doc/man/man1");
    let mut command = Command::new("asciidoctor");
    command
        .args(["-b", "manpage"])
        .args(["-a", concat!("revnumber=", env!("CARGO_PKG_VERSION"))]);
    #[cfg(feature = "cbor")]
    command.args(["-a", "cbor"]);
    #[cfg(feature = "json")]
    command.args(["-a", "json"]);
    #[cfg(feature = "msgpack")]
    command.args(["-a", "msgpack"]);
    #[cfg(feature = "toml")]
    command.args(["-a", "toml"]);
    #[cfg(feature = "yaml")]
    command.args(["-a", "yaml"]);
    command
        .args(["-D".as_ref(), out_dir.as_ref()])
        .args([
            man_dir.join("rscrypt.1.adoc"),
            man_dir.join("rscrypt-enc.1.adoc"),
            man_dir.join("rscrypt-dec.1.adoc"),
            man_dir.join("rscrypt-info.1.adoc"),
            man_dir.join("rscrypt-help.1.adoc"),
        ])
        .status()
}

fn main() {
    println!(
        "cargo:rerun-if-changed={}",
        env::current_dir().unwrap().join("doc/man").display()
    );

    match generate_man_page(env::var_os("OUT_DIR").unwrap()) {
        Ok(exit_status) => {
            if !exit_status.success() {
                println!("cargo:warning=Asciidoctor failed ({exit_status})");
            }
        }
        Err(err) => {
            println!("cargo:warning=failed to execute Asciidoctor ({err})");
        }
    }
}
