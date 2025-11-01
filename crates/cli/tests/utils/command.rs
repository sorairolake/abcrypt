// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

use assert_cmd::{Command, cargo::cargo_bin_cmd};

pub fn command() -> Command {
    let mut command = cargo_bin_cmd!("abcrypt");
    command.current_dir("tests");
    command
}
