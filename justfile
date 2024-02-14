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
    cargo fmt --all -- --config "format_code_in_doc_comments=true,wrap_comments=true"

# Run the linter
@clippy:
    cargo clippy --workspace -- -D warnings

# Apply lint suggestions
@clippy-fix:
    cargo clippy --workspace --fix --allow-dirty --allow-staged --lib --bins --examples --tests -- -D warnings

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

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w crates/*/README.md

# Build the book
@build-book:
    npx antora antora-playbook.yml

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
