<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: GPL-3.0-or-later
-->

# abcrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![MSRV][msrv-badge]
![License][license-badge]

**abcrypt** ([`abcrypt-cli`][version-url]) is a command-line utility for
encrypt and decrypt files using the [abcrypt encrypted data format].

## Installation

### From source

```sh
cargo install abcrypt-cli
```

If you want to enable optimizations such as LTO, set them using
[environment variables].

### From binaries

The [release page] contains pre-built binaries for Linux, macOS and Windows.

### How to build

Please see [BUILD.adoc].

## Usage

### Basic usage

Encrypt a file:

```sh
abcrypt encrypt data.txt > data.txt.abcrypt
```

Decrypt a file:

```sh
abcrypt decrypt data.txt.abcrypt > data.txt
```

### Provides information about the encryption parameters

Output as a human-readable string:

```sh
abcrypt information data.txt.abcrypt
```

Output:

```text
Parameters used: memoryCost = 32; timeCost = 3; parallelism = 4;
```

Output as JSON:

```sh
abcrypt information -j data.txt.abcrypt | jq
```

Output:

```json
{
  "memoryCost": 32,
  "timeCost": 3,
  "parallelism": 4
}
```

### Generate shell completion

`--generate-completion` option generates shell completions to standard output.

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

- [`abcrypt(1)`]
- [`abcrypt-encrypt(1)`]
- [`abcrypt-decrypt(1)`]
- [`abcrypt-argon2(1)`]
- [`abcrypt-information(1)`]
- [`abcrypt-help(1)`]

## Source code

The upstream repository is available at
<https://github.com/sorairolake/abcrypt.git>.

The source code is also available at:

- <https://gitlab.com/sorairolake/abcrypt.git>
- <https://codeberg.org/sorairolake/abcrypt.git>

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## Home page

<https://sorairolake.github.io/abcrypt/>

## License

Copyright (C) 2022 Shun Sakai (see [AUTHORS.adoc])

1.  This program is distributed under the terms of the _GNU General Public
    License v3.0 or later_.
2.  Some files are distributed under the terms of the _Creative Commons
    Attribution 4.0 International Public License_.

This project is compliant with version 3.2 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/abcrypt-cli?style=for-the-badge&logo=rust
[version-url]: https://crates.io/crates/abcrypt-cli
[msrv-badge]: https://img.shields.io/crates/msrv/abcrypt-cli?style=for-the-badge&logo=rust
[license-badge]: https://img.shields.io/crates/l/abcrypt-cli?style=for-the-badge
[abcrypt encrypted data format]: ../../docs/spec/FORMAT.adoc
[environment variables]: https://doc.rust-lang.org/cargo/reference/environment-variables.html#configuration-environment-variables
[release page]: https://github.com/sorairolake/abcrypt/releases
[BUILD.adoc]: BUILD.adoc
[`abcrypt(1)`]: https://sorairolake.github.io/abcrypt/book/cli/man/man1/abcrypt.1.html
[`abcrypt-encrypt(1)`]: https://sorairolake.github.io/abcrypt/book/cli/man/man1/abcrypt-encrypt.1.html
[`abcrypt-decrypt(1)`]: https://sorairolake.github.io/abcrypt/book/cli/man/man1/abcrypt-decrypt.1.html
[`abcrypt-argon2(1)`]: https://sorairolake.github.io/abcrypt/book/cli/man/man1/abcrypt-argon2.1.html
[`abcrypt-information(1)`]: https://sorairolake.github.io/abcrypt/book/cli/man/man1/abcrypt-information.1.html
[`abcrypt-help(1)`]: https://sorairolake.github.io/abcrypt/book/cli/man/man1/abcrypt-help.1.html
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: ../../CONTRIBUTING.adoc
[AUTHORS.adoc]: ../../AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
