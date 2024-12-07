// SPDX-FileCopyrightText: 2024 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_argon2() {
    utils::command::command()
        .arg("argon2")
        .arg("data/v1/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::contains("Type: Argon2id"))
        .stderr(predicate::str::contains("Version: 0x13"));
}

#[test]
fn argon2_if_non_existent_input_file() {
    let command = utils::command::command()
        .arg("argon2")
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

#[test]
fn argon2_if_input_file_is_invalid() {
    utils::command::command()
        .arg("argon2")
        .arg("data/data.txt")
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
fn long_version_for_argon2_command() {
    utils::command::command()
        .arg("argon2")
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/long-version.md"
        )));
}

#[test]
fn after_long_help_for_argon2_command() {
    utils::command::command()
        .arg("argon2")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/argon2-after-long-help.md"
        )));
}
