# SPDX-FileCopyrightText: 2023 Shun Sakai
#
# SPDX-License-Identifier: Apache-2.0 OR MIT

alias all := default
alias lint := clippy

# Run default recipe
default: build

# Build packages
@build:
    cargo build --workspace

# Remove generated artifacts
@clean:
    cargo clean

# Check packages
@check:
    cargo check --workspace

# Run tests
@test:
    cargo test

# Run the formatter
@fmt:
    cargo fmt --all

# Run the formatter with options
@fmt-with-options:
    cargo +nightly fmt --all

# Run the linter
@clippy:
    cargo clippy --workspace -- -D warnings

# Apply lint suggestions
@clippy-fix:
    cargo +nightly clippy --workspace --fix --allow-dirty --allow-staged -- -D warnings

# Configure the Meson project
setup-meson:
    #!/usr/bin/env bash
    cargo build -p abcrypt-capi
    cd crates/capi/examples
    meson setup builddir

# Build examples for the C API
build-capi-examples: setup-meson
    #!/usr/bin/env bash
    cd crates/capi/examples
    meson compile -C builddir

# Run clang-format
clang-format: setup-meson
    #!/usr/bin/env bash
    cd crates/capi/examples
    ninja -C builddir clang-format

# Run clang-tidy
clang-tidy: setup-meson
    #!/usr/bin/env bash
    cd crates/capi/examples
    ninja -C builddir clang-tidy

# Run tests for the Wasm bindings
@wasm-test:
    wasm-pack test --node crates/wasm

# Build examples for the Wasm bindings
@build-wasm-examples:
    wasm-pack build -t deno crates/wasm

# Run `deno fmt`
@fmt-wasm-examples:
    deno fmt crates/wasm/examples/*.ts

# Run `deno lint`
@lint-wasm-examples:
    deno lint crates/wasm/examples/*.ts

# Run `deno check`
@type-check-wasm-examples:
    deno check crates/wasm/examples/*.ts

# Configure a development environment for the Python bindings
setup-python:
    #!/usr/bin/env bash
    cd crates/python
    python3 -m venv venv
    source venv/bin/activate
    maturin develop
    pip3 install abcrypt-py[test,dev]

# Run tests for the Python bindings
python-test:
    #!/usr/bin/env bash
    cd crates/python
    source venv/bin/activate
    pytest

# Run the formatter for the Python bindings
python-fmt:
    #!/usr/bin/env bash
    cd crates/python
    source venv/bin/activate
    ruff format .

# Run the linter for the Python bindings
python-lint:
    #!/usr/bin/env bash
    cd crates/python
    source venv/bin/activate
    ruff check .

# Apply lint suggestions for the Python bindings
python-lint-fix:
    #!/usr/bin/env bash
    cd crates/python
    source venv/bin/activate
    ruff check --fix .

# Run `mypy`
python-type-check:
    #!/usr/bin/env bash
    cd crates/python
    source venv/bin/activate
    mypy .

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w crates/*/README.md

# Build the book
@build-book:
    npx antora antora-playbook.yml

# Build the Wasm bindings
build-wasm $CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1" $CARGO_PROFILE_RELEASE_STRIP="true":
    #!/usr/bin/env bash
    cd crates/wasm
    wasm-pack build -s sorairolake -t nodejs --release

# Publish the Wasm bindings
publish-wasm: build-wasm
    #!/usr/bin/env bash
    cd crates/wasm
    wasm-pack publish -a public

# Increment the version of the library
@bump-lib part:
    bump-my-version bump --config-file .bumpversion-lib.toml {{part}}
    cargo set-version --bump {{part}} -p abcrypt

# Increment the version of the command-line utility
@bump-cli part:
    cargo set-version --bump {{part}} -p abcrypt-cli

# Increment the version of the C API
@bump-capi part:
    bump-my-version bump --config-file .bumpversion-capi.toml {{part}}
    cargo set-version --bump {{part}} -p abcrypt-capi

# Increment the version of the Wasm bindings
@bump-wasm part:
    bump-my-version bump --config-file .bumpversion-wasm.toml {{part}}
    cargo set-version --bump {{part}} -p abcrypt-wasm

# Increment the version of the Python bindings
@bump-python part:
    bump-my-version bump --config-file .bumpversion-python.toml {{part}}
    cargo set-version --bump {{part}} -p abcrypt-py
