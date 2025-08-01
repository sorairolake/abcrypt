// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn completion() {
    utils::command::command()
        .arg("completion")
        .arg("bash")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    utils::command::command()
        .arg("completion")
        .arg("elvish")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    utils::command::command()
        .arg("completion")
        .arg("fish")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    utils::command::command()
        .arg("completion")
        .arg("nushell")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    utils::command::command()
        .arg("completion")
        .arg("powershell")
        .assert()
        .success()
        .stdout(predicate::ne(""));
    utils::command::command()
        .arg("completion")
        .arg("zsh")
        .assert()
        .success()
        .stdout(predicate::ne(""));
}

#[test]
fn infer_subcommand_name_for_completion_command() {
    utils::command::command()
        .arg("comp")
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("abcrypt-completion"));
    utils::command::command()
        .arg("c")
        .arg("-V")
        .assert()
        .success()
        .stdout(predicate::str::contains("abcrypt-completion"));
}

#[test]
fn completion_with_invalid_shell() {
    utils::command::command()
        .arg("completion")
        .arg("a")
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid value 'a' for '<SHELL>'"));
}
