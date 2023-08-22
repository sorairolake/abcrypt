// SPDX-FileCopyrightText: 2022 Shun Sakai
//
// SPDX-License-Identifier: GPL-3.0-or-later

pub trait StringExt {
    /// Removes trailing newline.
    fn remove_newline(&mut self);
}

impl StringExt for String {
    fn remove_newline(&mut self) {
        let len = self.trim_end_matches(&['\r', '\n'][..]).len();
        self.truncate(len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remove_lf() {
        let mut string = String::from("Hello, world!\n");
        string.remove_newline();
        assert_eq!(string, "Hello, world!");
    }

    #[test]
    fn remove_cr_lf() {
        let mut string = String::from("Hello, world!\r\n");
        string.remove_newline();
        assert_eq!(string, "Hello, world!");
    }

    #[test]
    fn remove_cr() {
        let mut string = String::from("Hello, world!\r");
        string.remove_newline();
        assert_eq!(string, "Hello, world!");
    }
}
