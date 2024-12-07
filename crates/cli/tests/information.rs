// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_information() {
    utils::command::command()
        .arg("information")
        .arg("data/v1/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 32; timeCost = 3; parallelism = 4;",
        ));
}

#[test]
fn validate_aliases_for_information_command() {
    utils::command::command()
        .arg("info")
        .arg("-V")
        .assert()
        .success();
    utils::command::command()
        .arg("i")
        .arg("-V")
        .assert()
        .success();
}

#[test]
fn information_if_non_existent_input_file() {
    let command = utils::command::command()
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
    utils::command::command()
        .arg("information")
        .arg("-j")
        .arg("data/v1/data.txt.abcrypt")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument '-j' found"));
}

#[cfg(feature = "json")]
#[test]
fn information_as_json() {
    utils::command::command()
        .arg("information")
        .arg("-j")
        .arg("data/v1/data.txt.abcrypt")
        .assert()
        .success()
        .stdout(predicate::eq(concat!(
            r#"{"memoryCost":32,"timeCost":3,"parallelism":4}"#,
            '\n'
        )));
}

#[test]
fn information_if_input_file_is_invalid() {
    utils::command::command()
        .arg("information")
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
fn long_version_for_information_command() {
    utils::command::command()
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
    utils::command::command()
        .arg("information")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(include_str!(
            "assets/information-after-long-help.md"
        )));
}
