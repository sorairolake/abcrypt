// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_decrypt() {
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2d/v0x10/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2d/v0x13/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2i/v0x10/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2i/v0x13/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2id/v0x10/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"));
}

#[test]
fn validate_aliases_for_decrypt_command() {
    utils::command::command()
        .arg("dec")
        .arg("-V")
        .assert()
        .success();
    utils::command::command()
        .arg("d")
        .arg("-V")
        .assert()
        .success();
}

#[test]
fn decrypt_if_non_existent_input_file() {
    let command = utils::command::command()
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
    let command = utils::command::command()
        .arg("decrypt")
        .arg("-o")
        .arg("data/dummy")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
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
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .stderr(predicate::str::ends_with(
            "cannot read both passphrase and input data from standard input\n",
        ));
}

#[test]
fn decrypt_if_input_file_is_invalid() {
    utils::command::command()
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
            "encrypted data is shorter than 164 bytes",
        ));
}

#[test]
fn decrypt_if_passphrase_is_incorrect() {
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
        .write_stdin("password")
        .assert()
        .failure()
        .code(65)
        .stderr(predicate::str::contains("passphrase is incorrect"))
        .stderr(predicate::str::contains("invalid header MAC"))
        .stderr(predicate::str::contains("MAC tag mismatch"));
}

#[test]
fn decrypt_from_unsupported_version() {
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("data/v0/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .failure()
        .code(65)
        .stderr(predicate::str::contains(
            "data is not a valid abcrypt encrypted file",
        ))
        .stderr(predicate::str::contains("unsupported version number `0`"));
}

#[test]
fn decrypt_verbose() {
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/v1/argon2d/v0x10/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 47104; timeCost = 1; parallelism = 1;",
        ));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/v1/argon2d/v0x13/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/v1/argon2i/v0x10/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 12288; timeCost = 3; parallelism = 1;",
        ));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/v1/argon2i/v0x13/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 9216; timeCost = 4; parallelism = 1;",
        ));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/v1/argon2id/v0x10/data.txt.abcrypt")
        .write_stdin("passphrase")
        .assert()
        .success()
        .stdout(predicate::eq("Hello, world!\n"))
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 7168; timeCost = 5; parallelism = 1;",
        ));
    utils::command::command()
        .arg("decrypt")
        .arg("--passphrase-from-stdin")
        .arg("-v")
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
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
    utils::command::command()
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
    utils::command::command()
        .arg("decrypt")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/decrypt-after-long-help.md"
        )));
}
