# SPDX-FileCopyrightText: 2023 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

alias lint := clippy

# Run default recipe
_default:
    just -l

# Build packages
build:
    cargo build --workspace

# Remove generated artifacts
clean:
    cargo clean

# Check packages
check:
    cargo check --workspace

# Run tests
test:
    cargo test -p abcrypt -p abcrypt-cli -p abcrypt-capi

# Run benchmarks
bench:
    cargo +nightly bench -p abcrypt

# Run the formatter
fmt:
    cargo fmt --all

# Run the formatter with options
fmt-with-options:
    cargo +nightly fmt --all

# Run the linter
clippy:
    cargo clippy --workspace -- -D warnings

# Apply lint suggestions
clippy-fix:
    cargo +nightly clippy --workspace --fix --allow-dirty --allow-staged -- -D warnings

# Build the library package documentation
doc $RUSTDOCFLAGS="--cfg docsrs":
    cargo +nightly doc -p abcrypt --all-features

# Configure the Meson project
[working-directory("crates/capi/examples")]
setup-meson:
    cargo build -p abcrypt-capi
    meson setup builddir

# Build examples for the C API
[working-directory("crates/capi/examples")]
build-capi-examples: setup-meson
    meson compile -C builddir

# Run clang-format
[working-directory("crates/capi/examples")]
clang-format: setup-meson
    ninja -C builddir clang-format

# Run clang-tidy
[working-directory("crates/capi/examples")]
clang-tidy: setup-meson
    ninja -C builddir clang-tidy

# Run tests for the Wasm bindings
wasm-test:
    wasm-pack test --node crates/wasm

# Build examples for the Wasm bindings
build-wasm-examples:
    wasm-pack build -t deno crates/wasm

# Run `deno fmt`
fmt-wasm-examples:
    deno fmt crates/wasm/examples/*.ts

# Run `deno lint`
lint-wasm-examples:
    deno lint crates/wasm/examples/*.ts

# Run `deno check`
type-check-wasm-examples:
    deno check crates/wasm/examples/*.ts

# Configure a development environment for the Python bindings
[working-directory("crates/python")]
setup-python:
    #!/usr/bin/env bash
    set -euCo pipefail
    python3 -m venv venv
    source venv/bin/activate
    maturin develop
    pip3 install abcrypt-py[test,dev]

# Run tests for the Python bindings
[working-directory("crates/python")]
python-test:
    #!/usr/bin/env bash
    set -euCo pipefail
    source venv/bin/activate
    pytest

# Run the formatter for the Python bindings
[working-directory("crates/python")]
python-fmt:
    #!/usr/bin/env bash
    set -euCo pipefail
    source venv/bin/activate
    ruff format .

# Run the linter for the Python bindings
[working-directory("crates/python")]
python-lint:
    #!/usr/bin/env bash
    set -euCo pipefail
    source venv/bin/activate
    ruff check .

# Apply lint suggestions for the Python bindings
[working-directory("crates/python")]
python-lint-fix:
    #!/usr/bin/env bash
    set -euCo pipefail
    source venv/bin/activate
    ruff check --fix .

# Run `mypy`
[working-directory("crates/python")]
python-type-check:
    #!/usr/bin/env bash
    set -euCo pipefail
    source venv/bin/activate
    mypy .

# Run the linter for GitHub Actions workflow files
lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
fmt-readme:
    npx prettier -w crates/*/README.md

# Build the book
build-book:
    npx antora antora-playbook.yml

# Build the Wasm bindings
[working-directory("crates/wasm")]
build-wasm $CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1" $CARGO_PROFILE_RELEASE_STRIP="true":
    wasm-pack build -s sorairolake -t nodejs --release

# Publish the Wasm bindings
[working-directory("crates/wasm")]
publish-wasm: build-wasm
    wasm-pack publish -a public

# Increment the version of the library
bump-lib part:
    bump-my-version bump --config-file .bumpversion-lib.toml {{ part }}
    cargo set-version --bump {{ part }} -p abcrypt

# Increment the version of the command-line utility
bump-cli part:
    bump-my-version bump --config-file .bumpversion-cli.toml {{ part }}
    cargo set-version --bump {{ part }} -p abcrypt-cli

# Increment the version of the C API
bump-capi part:
    bump-my-version bump --config-file .bumpversion-capi.toml {{ part }}
    cargo set-version --bump {{ part }} -p abcrypt-capi

# Increment the version of the Wasm bindings
bump-wasm part:
    bump-my-version bump --config-file .bumpversion-wasm.toml {{ part }}
    cargo set-version --bump {{ part }} -p abcrypt-wasm

# Increment the version of the Python bindings
bump-python part:
    bump-my-version bump --config-file .bumpversion-python.toml {{ part }}
    cargo set-version --bump {{ part }} -p abcrypt-py
