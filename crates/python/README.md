<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# Python Bindings for abcrypt

[![CI][ci-badge]][ci-url]
[![PyPI Version][pypi-version-badge]][pypi-version-url]
[![crates.io Version][crates-version-badge]][crates-version-url]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**abcrypt-py** is the Python bindings for the [`abcrypt`] crate.

## Usage

### Installation

To install this library:

```sh
pip install abcrypt-py
```

### Example

```py
from typing import Final

import abcrypt_py

DATA: Final[bytes] = b"Hello, world!\n"
PASSPHRASE: Final[bytes] = b"passphrase"

# Encrypt `DATA` using `PASSPHRASE`.
ciphertext = abcrypt_py.encrypt(DATA, PASSPHRASE)
assert ciphertext != DATA

# And extract the Argon2 parameters from it.
params = abcrypt_py.Params(ciphertext)
assert params.memory_cost == 19456
assert params.time_cost == 2
assert params.parallelism == 1

# And decrypt it back.
plaintext = abcrypt_py.decrypt(ciphertext, PASSPHRASE)
assert plaintext == DATA
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

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## License

Copyright &copy; 2022&ndash;2024 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.0 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[pypi-version-badge]: https://img.shields.io/pypi/v/abcrypt-py?style=for-the-badge&logo=pypi
[pypi-version-url]: https://pypi.org/project/abcrypt-py/
[crates-version-badge]: https://img.shields.io/crates/v/abcrypt-py?style=for-the-badge&logo=rust
[crates-version-url]: https://crates.io/crates/abcrypt-py
[docs-badge]: https://img.shields.io/docsrs/abcrypt-py?style=for-the-badge&logo=docsdotrs&label=Docs.rs
[docs-url]: https://docs.rs/abcrypt-py
[license-badge]: https://img.shields.io/crates/l/abcrypt-py?style=for-the-badge
[`abcrypt`]: https://crates.io/crates/abcrypt
[maturin]: https://www.maturin.rs/
[CHANGELOG.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/crates/python/CHANGELOG.adoc
[CONTRIBUTING.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/CONTRIBUTING.adoc
[AUTHORS.adoc]: https://github.com/sorairolake/abcrypt/blob/develop/AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
