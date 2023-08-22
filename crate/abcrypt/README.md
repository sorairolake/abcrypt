<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# scryptenc-rs

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**scryptenc-rs** ([`scryptenc`][version-url]) is an implementation of the
scrypt encrypted data format.

The format is defined [here][specification-url].

## Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
scryptenc = "0.7.1"
```

### Crate features

#### `std`

Enables features that depend on the standard library. This is enabled by
default.

### `no_std` support

This supports `no_std` mode. Disables the `default` feature to enable this.

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.60.0.

## Changelog

Please see [CHANGELOG.adoc](CHANGELOG.adoc).

## Contributing

Please see [CONTRIBUTING.adoc](CONTRIBUTING.adoc).

## License

Copyright &copy; 2022&ndash;2023 Shun Sakai (see [AUTHORS.adoc](AUTHORS.adoc))

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

See [COPYING](COPYING) for more details.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/scryptenc-rs/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/scryptenc-rs/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/scryptenc?style=for-the-badge
[version-url]: https://crates.io/crates/scryptenc
[docs-badge]: https://img.shields.io/docsrs/scryptenc?label=Docs.rs&logo=docsdotrs&style=for-the-badge
[docs-url]: https://docs.rs/scryptenc
[license-badge]: https://img.shields.io/crates/l/scryptenc?style=for-the-badge
[specification-url]: https://github.com/Tarsnap/scrypt/blob/1.3.1/FORMAT
