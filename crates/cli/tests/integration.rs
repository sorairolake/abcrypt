// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

mod utils;

use predicates::prelude::predicate;

#[test]
fn without_subcommand() {
    utils::command::command()
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains(
            "requires a subcommand but one was not provided",
        ));
}
