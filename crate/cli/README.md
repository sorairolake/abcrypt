<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: GPL-3.0-or-later
-->

# abcrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![License][license-badge]

**abcrypt** ([`abcrypt-cli`][version-url]) is a command-line utility for
encrypt and decrypt files using the abcrypt format.

## Installation

### From source

```sh
cargo install abcrypt-cli
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
abcrypt encrypt file > file.abcrypt
```

Decrypt a file:

```sh
abcrypt decrypt file.abcrypt > file
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
abcrypt --generate-completion bash > abcrypt.bash
```

## Command-line options

Please see the following:

- [`abcrypt(1)`](doc/man/man1/abcrypt.1.adoc)
- [`abcrypt-encrypt(1)`](doc/man/man1/abcrypt-encrypt.1.adoc)
- [`abcrypt-decrypt(1)`](doc/man/man1/abcrypt-decrypt.1.adoc)
- [`abcrypt-information(1)`](doc/man/man1/abcrypt-information.1.adoc)
- [`abcrypt-help(1)`](doc/man/man1/abcrypt-help.1.adoc)

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Copyright &copy; 2022&ndash;2023 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

1. This program is distributed under the terms of the _GNU General Public
   License v3.0 or later_.
2. Some files are distributed under the terms of the _Creative Commons
   Attribution 4.0 International Public License_.

This project is compliant with version 3.0 of the
[_REUSE Specification_](https://reuse.software/spec/). See [COPYING](COPYING)
and copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/abcrypt-cli?style=for-the-badge
[version-url]: https://crates.io/crates/abcrypt-cli
[license-badge]: https://img.shields.io/crates/l/abcrypt-cli?style=for-the-badge
[release-page-url]: https://github.com/sorairolake/abcrypt/releases
