<!--
SPDX-FileCopyrightText: 2022 Shun Sakai

SPDX-License-Identifier: Apache-2.0 OR MIT
-->

# Wasm Bindings for abcrypt

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

This crate ([`abcrypt-wasm`][version-url]) is the Wasm bindings for the
[`abcrypt`] crate.

## Usage

### Build

You will need [`wasm-pack`] to build this crate.

```sh
wasm-pack build
```

This will generate build artifacts in the `pkg` directory.

### Example

```ts
import * as assert from "https://deno.land/std@0.213.0/assert/mod.ts";

import * as abcrypt from "./pkg/abcrypt_wasm.js";

const data = new TextEncoder().encode("Hello, world!\n");
const passphrase = new TextEncoder().encode("passphrase");

// Encrypt `data` using `passphrase`.
const ciphertext = abcrypt.encryptWithParams(data, passphrase, 32, 3, 4);
assert.assertNotEquals(ciphertext, data);

// And decrypt it back.
const plaintext = abcrypt.decrypt(ciphertext, passphrase);
assert.assertEquals(plaintext, data);
```

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.70.0.

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

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/abcrypt/CI.yaml?branch=develop&label=CI&logo=github&style=for-the-badge
[ci-url]: https://github.com/sorairolake/abcrypt/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/abcrypt-wasm?style=for-the-badge
[version-url]: https://crates.io/crates/abcrypt-wasm
[docs-badge]: https://img.shields.io/docsrs/abcrypt-wasm?label=Docs.rs&logo=docsdotrs&style=for-the-badge
[docs-url]: https://docs.rs/abcrypt-wasm
[license-badge]: https://img.shields.io/crates/l/abcrypt-wasm?style=for-the-badge
[`abcrypt`]: https://crates.io/crates/abcrypt
[`wasm-pack`]: https://rustwasm.github.io/wasm-pack/
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: ../../CONTRIBUTING.adoc
[AUTHORS.adoc]: ../../AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec/
