// SPDX-FileCopyrightText: 2023 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn main() {
    let crate_dir = env!("CARGO_MANIFEST_DIR");
    cbindgen::generate(crate_dir)
        .expect("failed to generate bindings")
        .write_to_file("include/abcrypt.h");
}
