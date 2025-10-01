// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

use crate::utils::command;

#[test]
fn without_subcommand() {
    command::command()
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "requires a subcommand but one was not provided",
        ));
}
