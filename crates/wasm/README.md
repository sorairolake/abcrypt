<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# Wasm Bindings for abcrypt

[![CI][ci-badge]][ci-url]
[![npm Version][npm-version-badge]][npm-version-url]
[![crates.io Version][crates-version-badge]][crates-version-url]
![MSRV][msrv-badge]
[![Docs][docs-badge]][docs-url]
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

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.74.0.

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

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.2 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[npm-version-badge]: https://img.shields.io/npm/v/%40sorairolake%2Fabcrypt-wasm?style=for-the-badge&logo=npm
[npm-version-url]: https://www.npmjs.com/package/@sorairolake/abcrypt-wasm
[crates-version-badge]: https://img.shields.io/crates/v/abcrypt-wasm?style=for-the-badge&logo=rust
[crates-version-url]: https://crates.io/crates/abcrypt-wasm
[msrv-badge]: https://img.shields.io/crates/msrv/abcrypt-wasm?style=for-the-badge&logo=rust
[docs-badge]: https://img.shields.io/docsrs/abcrypt-wasm?style=for-the-badge&logo=docsdotrs&label=Docs.rs
[docs-url]: https://docs.rs/abcrypt-wasm
[license-badge]: https://img.shields.io/crates/l/abcrypt-wasm?style=for-the-badge
[`abcrypt`]: https://crates.io/crates/abcrypt
[`wasm-pack`]: https://rustwasm.github.io/wasm-pack/
[CHANGELOG.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/crates/wasm/CHANGELOG.adoc
[CONTRIBUTING.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/CONTRIBUTING.adoc
[AUTHORS.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
