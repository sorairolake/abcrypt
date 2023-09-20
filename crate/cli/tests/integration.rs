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

use assert_cmd::Command;
use predicates::prelude::predicate;

fn command() -> Command {
    let mut command = Command::cargo_bin("abcrypt").unwrap();
    command.current_dir("tests");
    command
}

#[test]
fn generate_completion_conflicts_with_subcommands() {
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("encrypt")
        .assert()
        .failure()
        .code(2);
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("decrypt")
        .assert()
        .failure()
        .code(2);
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("information")
        .assert()
        .failure()
        .code(2);
}

#[test]
fn long_version() {
    command()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/long-version.md"
        )));
}

#[test]
fn after_long_help() {
    command()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/after-long-help.md"
        )));
}

#[test]
fn basic_encrypt() {
    command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success();
}

#[test]
fn validate_aliases_for_encrypt_command() {
    command().arg("enc").arg("-V").assert().success();
    command().arg("e").arg("-V").assert().success();
}

#[test]
fn validate_m_parameter_with_unit_for_encrypt_command() {
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 1;",
        ));
}

#[test]
fn validate_m_parameter_without_unit_for_encrypt_command() {
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 1;",
        ));
}

#[test]
fn validate_m_parameter_with_byte_prefix_for_encrypt_command() {
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 1;",
        ));
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 1;",
        ));
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 1;",
        ));
}

#[test]
fn validate_m_parameter_with_invalid_unit_for_encrypt_command() {
    command()
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
        .stderr(predicate::str::contains("The character 'A' is incorrect. 'B', 'K', 'M', 'G', 'T', 'P' or no character is expected"));
    command()
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
        .stderr(predicate::str::contains("The character 'L' is incorrect. 'B', 'K', 'M', 'G', 'T', 'P' or no character is expected"));
}

#[test]
fn validate_m_parameter_with_nan_for_encrypt_command() {
    command()
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
            "The character 'n' is not a number",
        ));
    command()
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
            "The character 'n' is not a number",
        ));
    command()
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
            "The character 'n' is not a number",
        ));
}

#[test]
fn validate_m_parameter_ranges_for_encrypt_command() {
    command()
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
    command()
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
            "Parameters used: m_cost = 8; t_cost = 2; p_cost = 1;",
        ));
    command()
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
fn validate_t_parameter_with_nan_for_encrypt_command() {
    command()
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
fn validate_t_parameter_ranges_for_encrypt_command() {
    command()
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
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 1; p_cost = 1;",
        ));
    command()
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
fn validate_p_parameter_with_nan_for_encrypt_command() {
    command()
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
fn validate_p_parameter_ranges_for_encrypt_command() {
    command()
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
    command()
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
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 2;",
        ));
    command()
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
    command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from stdin\n",
        ));
}

#[test]
fn encrypt_verbose() {
    command()
        .arg("encrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: m_cost = 19456; t_cost = 2; p_cost = 1;",
        ));
}

#[test]
fn long_version_for_encrypt_command() {
    command()
        .arg("encrypt")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/long-version.md"
        )));
}

#[test]
fn after_long_help_for_encrypt_command() {
    command()
        .arg("encrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/encrypt-after-long-help.md"
        )));
}

#[test]
fn basic_decrypt() {
    command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
}

#[test]
fn validate_aliases_for_decrypt_command() {
    command().arg("dec").arg("-V").assert().success();
    command().arg("d").arg("-V").assert().success();
}

#[test]
fn validate_conflicts_if_reading_from_stdin_for_decrypt_command() {
    command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from stdin\n",
        ));
}

#[test]
fn decrypt_verbose() {
    command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: m_cost = 32; t_cost = 3; p_cost = 4;",
        ));
}

#[test]
fn long_version_for_decrypt_command() {
    command()
        .arg("decrypt")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/long-version.md"
        )));
}

#[test]
fn after_long_help_for_decrypt_command() {
    command()
        .arg("decrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/decrypt-after-long-help.md"
        )));
}

#[test]
fn basic_information() {
    command()
        .arg("information")
        .arg("data/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: m_cost = 32; t_cost = 3; p_cost = 4;",
        ));
}

#[test]
fn validate_aliases_for_information_command() {
    command().arg("info").arg("-V").assert().success();
    command().arg("i").arg("-V").assert().success();
}

#[cfg(not(feature = "json",))]
#[test]
fn information_command_without_default_feature() {
    command()
        .arg("information")
        .arg("-j")
        .arg("data/data.txt.abcrypt")
        .assert()
        .failure()
        .code(2);
}

#[cfg(feature = "json")]
#[test]
fn information_as_json() {
    command()
        .arg("information")
        .arg("-j")
        .arg("data/data.txt.abcrypt")
        .assert()
        .success()
        .stdout(predicate::eq(concat!(
            r#"{"m_cost":32,"t_cost":3,"p_cost":4}"#,
            '\n'
        )));
}

#[test]
fn long_version_for_information_command() {
    command()
        .arg("information")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/long-version.md"
        )));
}

#[test]
fn after_long_help_for_information_command() {
    command()
        .arg("information")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "../src/static/information-after-long-help.md"
        )));
}
