<!--
SPDX-FileCopyrightText: 2023 Shun Sakai

SPDX-License-Identifier: CC-BY-4.0
-->

# Wasm Bindings for abcrypt

[![CI][ci-badge]][ci-url]
[![npm Version][npm-version-badge]][npm-version-url]
![License][license-badge]

**abcrypt-wasm** is the Wasm bindings for the [`abcrypt`] crate.

## Usage

### Installation

To install this library:

```sh
npm install @sorairolake/abcrypt-wasm
```

### Build

You will need [`wasm-pack`] to build this crate.

```sh
wasm-pack build
```

This will generate build artifacts in the `pkg` directory.

## Examples

Please see the [examples] directory for examples of using this library.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.88.0.

## Source code

The upstream repository is available at
<https://github.com/sorairolake/abcrypt.git>.

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## Home page

<https://sorairolake.github.io/abcrypt/>

## License

Copyright (C) 2023 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.3 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[npm-version-badge]: https://img.shields.io/npm/v/%40sorairolake%2Fabcrypt-wasm?style=for-the-badge&logo=npm
[npm-version-url]: https://www.npmjs.com/package/@sorairolake/abcrypt-wasm
[license-badge]: https://img.shields.io/npm/l/%40sorairolake%2Fabcrypt-wasm?style=for-the-badge
[`abcrypt`]: https://crates.io/crates/abcrypt
[`wasm-pack`]: https://rustwasm.github.io/wasm-pack/
[examples]: examples
[CHANGELOG.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/crates/wasm/CHANGELOG.adoc
[CONTRIBUTING.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/CONTRIBUTING.adoc
[AUTHORS.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec-3.3/
