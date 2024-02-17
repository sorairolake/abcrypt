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
        .code(2)
        .stderr(predicate::str::contains(
            "the subcommand 'encrypt' cannot be used with '--generate-completion <SHELL>'",
        ));
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("decrypt")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the subcommand 'decrypt' cannot be used with '--generate-completion <SHELL>'",
        ));
    command()
        .arg("--generate-completion")
        .arg("bash")
        .arg("information")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "the subcommand 'information' cannot be used with '--generate-completion <SHELL>'",
        ));
}

#[test]
fn generate_completion() {
    command()
        .arg("--generate-completion")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("elvish")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("nushell")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    command()
        .arg("--generate-completion")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::ne(""));
}

#[test]
fn generate_completion_with_invalid_shell() {
    command()
        .arg("--generate-completion")
        .arg("a")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "invalid value 'a' for '--generate-completion <SHELL>'",
        ));
}

#[test]
fn long_version() {
    command()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help() {
    command()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/after-long-help.md"
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
fn encrypt_if_non_existent_input_file() {
    let command = command()
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
    let command = command()
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn validate_memory_cost_without_unit_for_encrypt_command() {
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn validate_memory_cost_with_byte_prefix_for_encrypt_command() {
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
}

#[test]
fn validate_memory_cost_with_invalid_unit_for_encrypt_command() {
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
        .stderr(predicate::str::contains("the character 'A' is incorrect"));
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
        .stderr(predicate::str::contains("the character 'L' is incorrect"));
}

#[test]
fn validate_memory_cost_with_nan_for_encrypt_command() {
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
            "the character 'n' is not a number",
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
            "the character 'n' is not a number",
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
            "the character 'n' is not a number",
        ));
}

#[test]
fn validate_memory_cost_ranges_for_encrypt_command() {
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
            "Parameters used: memoryCost = 8; timeCost = 2; parallelism = 1;",
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
fn validate_time_cost_with_nan_for_encrypt_command() {
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
fn validate_time_cost_ranges_for_encrypt_command() {
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
            "Parameters used: memoryCost = 19456; timeCost = 1; parallelism = 1;",
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
fn validate_parallelism_with_nan_for_encrypt_command() {
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
fn validate_parallelism_ranges_for_encrypt_command() {
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 2;",
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
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
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
            "assets/long-version.md"
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
            "assets/encrypt-after-long-help.md"
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
fn decrypt_if_non_existent_input_file() {
    let command = command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("non_existent.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(66)
        .stderr(predicate::str::contains(
            "could not read data from non_existent.txt.abcrypt",
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
fn decrypt_if_output_is_directory() {
    let command = command()
        .arg("decrypt")
        .arg("-o")
        .arg("data/dummy")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.abcrypt")
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
fn decrypt_if_input_file_is_invalid() {
    command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(65)
        .stderr(predicate::str::contains(
            "data is not a valid abcrypt encrypted file",
        ))
        .stderr(predicate::str::contains(
            "encrypted data is shorter than 156 bytes",
        ));
}

#[test]
fn decrypt_if_passphrase_is_incorrect() {
    command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/data.txt.abcrypt")
        .write_stdin("password")
        .assert()
        .failure()
        .code(65)
        .stderr(predicate::str::contains("passphrase is incorrect"))
        .stderr(predicate::str::contains("invalid header MAC"))
        .stderr(predicate::str::contains("MAC tag mismatch"));
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
            "Parameters used: memoryCost = 32; timeCost = 3; parallelism = 4;",
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
            "assets/long-version.md"
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
            "assets/decrypt-after-long-help.md"
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
            "Parameters used: memoryCost = 32; timeCost = 3; parallelism = 4;",
        ));
}

#[test]
fn validate_aliases_for_information_command() {
    command().arg("info").arg("-V").assert().success();
    command().arg("i").arg("-V").assert().success();
}

#[test]
fn information_if_non_existent_input_file() {
    let command = command()
        .arg("information")
        .arg("non_existent.txt.abcrypt")
        .assert()
        .failure()
        .code(66)
        .stderr(predicate::str::contains(
            "could not read data from non_existent.txt.abcrypt",
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

#[cfg(not(feature = "json"))]
#[test]
fn information_command_without_default_feature() {
    command()
        .arg("information")
        .arg("-j")
        .arg("data/data.txt.abcrypt")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument '-j' found"));
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
            r#"{"memoryCost":32,"timeCost":3,"parallelism":4}"#,
            '\n'
        )));
}

#[test]
fn information_if_input_file_is_invalid() {
    command()
        .arg("information")
        .arg("data/data.txt")
        .assert()
        .failure()
        .code(65)
        .stderr(predicate::str::contains(
            "data is not a valid abcrypt encrypted file",
        ))
        .stderr(predicate::str::contains(
            "encrypted data is shorter than 156 bytes",
        ));
}

#[test]
fn long_version_for_information_command() {
    command()
        .arg("information")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
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
            "assets/information-after-long-help.md"
        )));
}
