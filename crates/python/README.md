<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# Python Bindings for abcrypt

[![CI][ci-badge]][ci-url]
[![PyPI Version][pypi-version-badge]][pypi-version-url]
![PyPI Python Version][pypi-python-version-badge]
[![crates.io Version][crates-version-badge]][crates-version-url]
![MSRV][msrv-badge]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**abcrypt-py** is the Python bindings for the [`abcrypt`] crate.

## Usage

### Installation

To install this library:

```sh
pip install abcrypt-py
```

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.74.0.

## Development

[maturin] is required for development of this library.

```sh
python3 -m venv venv
source venv/bin/activate
maturin develop
pip3 install abcrypt-py[test,dev]
```

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

## License

Copyright (C) 2022-2024 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.2 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[pypi-version-badge]: https://img.shields.io/pypi/v/abcrypt-py?style=for-the-badge&logo=pypi
[pypi-version-url]: https://pypi.org/project/abcrypt-py/
[pypi-python-version-badge]: https://img.shields.io/pypi/pyversions/abcrypt-py?style=for-the-badge&logo=python
[crates-version-badge]: https://img.shields.io/crates/v/abcrypt-py?style=for-the-badge&logo=rust
[crates-version-url]: https://crates.io/crates/abcrypt-py
[msrv-badge]: https://img.shields.io/crates/msrv/abcrypt-py?style=for-the-badge&logo=rust
[docs-badge]: https://img.shields.io/docsrs/abcrypt-py?style=for-the-badge&logo=docsdotrs&label=Docs.rs
[docs-url]: https://docs.rs/abcrypt-py
[license-badge]: https://img.shields.io/crates/l/abcrypt-py?style=for-the-badge
[`abcrypt`]: https://crates.io/crates/abcrypt
[maturin]: https://www.maturin.rs/
[CHANGELOG.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/crates/python/CHANGELOG.adoc
[CONTRIBUTING.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/CONTRIBUTING.adoc
[AUTHORS.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
