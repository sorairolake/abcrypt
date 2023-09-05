<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# abcrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**abcrypt** is an implementation of the abcrypt encrypted data format.

This crate implements version 0 of the abcrypt encrypted data format.

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
abcrypt = "0.2.0"
```

### Crate features

#### `alloc`

Enables features that require an allocator. This is enabled by default (implied
by `std`).

#### `std`

Enables features that depend on the standard library. This is enabled by
default.

### `no_std` support

This supports `no_std` mode. Disables the `default` feature to enable this.

Note that the memory blocks used by Argon2 when calculating a derived key is
limited to 256 KiB when the `alloc` feature is disabled.

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.65.0.

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## License

Copyright &copy; 2022&ndash;2023 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.0 of the [_REUSE Specification_]. See
[COPYING] and copyright notices of individual files for more details on
copyright and licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/abcrypt?style=for-the-badge
[version-url]: https://crates.io/crates/abcrypt
[docs-badge]: https://img.shields.io/docsrs/abcrypt?label=Docs.rs&logo=docsdotrs&style=for-the-badge
[docs-url]: https://docs.rs/abcrypt
[license-badge]: https://img.shields.io/crates/l/abcrypt?style=for-the-badge
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: ../../CONTRIBUTING.adoc
[AUTHORS.adoc]: ../../AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
[COPYING]: ../../COPYING
