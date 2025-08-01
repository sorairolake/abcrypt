// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn basic_information() {
    utils::command::command()
        .arg("information")
        .arg("data/v1/argon2d/v0x10/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 47104; timeCost = 1; parallelism = 1;",
        ));
    utils::command::command()
        .arg("information")
        .arg("data/v1/argon2d/v0x13/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 19456; timeCost = 2; parallelism = 1;",
        ));
    utils::command::command()
        .arg("information")
        .arg("data/v1/argon2i/v0x10/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 12288; timeCost = 3; parallelism = 1;",
        ));
    utils::command::command()
        .arg("information")
        .arg("data/v1/argon2i/v0x13/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 9216; timeCost = 4; parallelism = 1;",
        ));
    utils::command::command()
        .arg("information")
        .arg("data/v1/argon2id/v0x10/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 7168; timeCost = 5; parallelism = 1;",
        ));
    utils::command::command()
        .arg("information")
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
        .assert()
        .success()
        .stderr(predicate::str::starts_with(
            "Parameters used: memoryCost = 32; timeCost = 3; parallelism = 4;",
        ));
}

#[test]
fn infer_subcommand_name_for_information_command() {
    utils::command::command()
        .arg("info")
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("abcrypt-information"));
    utils::command::command()
        .arg("i")
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("abcrypt-information"));
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
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
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
        .arg("data/v1/argon2id/v0x13/data.txt.abcrypt")
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
