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

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_encrypt() {
    utils::command::command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success();
}

#[test]
fn validate_aliases_for_encrypt_command() {
    utils::command::command()
        .arg("enc")
        .arg("-V")
        .assert()
        .success();
    utils::command::command()
        .arg("e")
        .arg("-V")
        .assert()
        .success();
}

#[test]
fn encrypt_if_non_existent_input_file() {
    let command = utils::command::command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .arg("non_existent.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(66)
        .stderr(predicate::str::contains(
            "could not read data from non_existent.txt",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains(
            "The system cannot find the file specified. (os error 2)",
        ));
    } else {
        command.stderr(predicate::str::contains(
            "No such file or directory (os error 2)",
        ));
    }
}

#[test]
fn encrypt_if_output_is_directory() {
    let command = utils::command::command()
        .arg("encrypt")
        .arg("-o")
        .arg("data/dummy")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "could not write data to data/dummy",
        ));
    if cfg!(windows) {
        command.stderr(predicate::str::contains("Access is denied. (os error 5)"));
    } else {
        command.stderr(predicate::str::contains("Is a directory (os error 21)"));
    }
}

#[test]
fn validate_memory_cost_with_unit_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19922944 B")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn validate_memory_cost_without_unit_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19922944")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn validate_memory_cost_with_byte_prefix_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19456 KiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19.00 MiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19MiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn validate_memory_cost_with_invalid_unit_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19922944 A")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("the character 'A' is incorrect"));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("19.00LiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("the character 'L' is incorrect"));
}

#[test]
fn validate_memory_cost_with_nan_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("n B")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the character 'n' is not a number",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("n")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the character 'n' is not a number",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("nKiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the character 'n' is not a number",
        ));
}

#[test]
fn validate_memory_cost_ranges_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("7 KiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "7 KiB is not in 8 KiB..=4294967295 KiB",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("8 KiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 8; timeCost = 2; parallelism = 1;",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-m")
        .arg("4294967296 KiB")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "4294967296 KiB is not in 8 KiB..=4294967295 KiB",
        ));
}

#[test]
fn validate_time_cost_with_nan_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-t")
        .arg("n")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid digit found in string"));
}

#[test]
fn validate_time_cost_ranges_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-t")
        .arg("0")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("0 is not in 1..=4294967295"));
    utils::command::command()
        .arg("encrypt")
        .arg("-t")
        .arg("1")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 1; parallelism = 1;",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-t")
        .arg("4294967296")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "4294967296 is not in 1..=4294967295",
        ));
}

#[test]
fn validate_parallelism_with_nan_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-p")
        .arg("n")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid digit found in string"));
}

#[test]
fn validate_parallelism_ranges_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("-p")
        .arg("0")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("0 is not in 1..=16777215"));
    utils::command::command()
        .arg("encrypt")
        .arg("-p")
        .arg("2")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 2;",
        ));
    utils::command::command()
        .arg("encrypt")
        .arg("-p")
        .arg("16777216")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("16777216 is not in 1..=16777215"));
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from standard input\n",
        ));
}

#[test]
fn encrypt_verbose() {
    utils::command::command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn long_version_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help_for_encrypt_command() {
    utils::command::command()
        .arg("encrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/encrypt-after-long-help.md"
        )));
}
