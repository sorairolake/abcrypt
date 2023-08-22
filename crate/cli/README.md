<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: GPL-3.0-or-later
-->

# rscrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![License][license-badge]

**rscrypt** ([`scryptenc-cli`][version-url]) is a command-line utility for
encrypt and decrypt files.

This is a Rust implementation of `scrypt(1)`.

![Demonstration video](asset/demo.gif)

## Installation

### From source

```sh
cargo install scryptenc-cli
```

### From binaries

The [release page][release-page-url] contains pre-built binaries for Linux,
macOS and Windows.

### How to build

Please see [BUILD.adoc](BUILD.adoc).

## Usage

### Basic usage

Encrypt a file:

```sh
rscrypt enc file file.enc
```

Decrypt a file:

```sh
rscrypt dec file.enc file
```

### Generate shell completion

`--generate-completion` option generates shell completions to stdout.

The following shells are supported:

- `bash`
- `elvish`
- `fish`
- `nushell`
- `powershell`
- `zsh`

Example:

```sh
rscrypt --generate-completion bash > rscrypt.bash
```

## Command-line options

Please see the following:

- [`rscrypt(1)`][rscrypt-man-url]
- [`rscrypt-enc(1)`][rscrypt-enc-man-url]
- [`rscrypt-dec(1)`][rscrypt-dec-man-url]
- [`rscrypt-info(1)`][rscrypt-info-man-url]
- [`rscrypt-help(1)`][rscrypt-help-man-url]

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## Acknowledgment

This program is inspired by the
[scrypt encryption utility](https://www.tarsnap.com/scrypt.html), and built on
top of the [`scryptenc`](https://crates.io/crates/scryptenc) crate.

## License

Copyright &copy; 2022&ndash;2023 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

1. This program is distributed under the terms of the _GNU General Public
   License v3.0 or later_.
2. Some files are distributed under the terms of the _Creative Commons
   Attribution 4.0 International Public License_.

See [COPYING](COPYING) for more details.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/rscrypt/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/rscrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/scryptenc-cli?style=for-the-badge
[version-url]: https://crates.io/crates/scryptenc-cli
[license-badge]: https://img.shields.io/crates/l/scryptenc-cli?style=for-the-badge
[release-page-url]: https://github.com/sorairolake/rscrypt/releases
[rscrypt-man-url]: https://sorairolake.github.io/rscrypt/man/rscrypt.1.html
[rscrypt-enc-man-url]: https://sorairolake.github.io/rscrypt/man/rscrypt-enc.1.html
[rscrypt-dec-man-url]: https://sorairolake.github.io/rscrypt/man/rscrypt-dec.1.html
[rscrypt-info-man-url]: https://sorairolake.github.io/rscrypt/man/rscrypt-info.1.html
[rscrypt-help-man-url]: https://sorairolake.github.io/rscrypt/man/rscrypt-help.1.html
