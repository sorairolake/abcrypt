<!--
SPDX-FileCopyrightText: 2023 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# abcrypt

[![CI][ci-badge]][ci-url]

**abcrypt** is a simple, modern and secure file encryption tool, file format
and Rust library.

## Crates

| Name                                                                           | Version                                                                                                             | Description                                    |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------- |
| [`abcrypt`](https://github.com/sorairolake/abcrypt/tree/develop/crate/abcrypt) | [![Version](https://img.shields.io/crates/v/abcrypt?style=for-the-badge)](https://crates.io/crates/abcrypt)         | The abcrypt format reference implementation.   |
| [`abcrypt-cli`](https://github.com/sorairolake/abcrypt/tree/develop/crate/cli) | [![Version](https://img.shields.io/crates/v/abcrypt-cli?style=for-the-badge)](https://crates.io/crates/abcrypt-cli) | File encryption tool using the abcrypt format. |

## Format specification

The format specification is at [FORMAT.adoc](doc/FORMAT.adoc).

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Please see [COPYING](COPYING).

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
