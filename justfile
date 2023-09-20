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
    cargo clippy --workspace --fix --allow-dirty --allow-staged --lib --tests --examples -- -D warnings

# Build examples for the C API
build-capi-examples:
    #!/usr/bin/env bash
    cargo build -p abcrypt-capi
    cd crate/capi/examples
    meson setup builddir
    meson compile -C builddir

# Run clang-format
@clang-format:
    clang-format -i crate/capi/examples/*.{cpp,hpp}

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w README.md crate/*/README.md

# Build the book
@build-book:
    npx antora antora-playbook.yml

# Increment the version of the library
@bump-lib part:
    bump2version --config-file .bumpversion-lib.cfg {{part}}
    cargo set-version --bump {{part}} -p abcrypt

# Increment the version of the command-line utility
@bump-cli part:
    bump2version --config-file .bumpversion-cli.cfg {{part}}
    cargo set-version --bump {{part}} -p abcrypt-cli

# Increment the version of the C API
@bump-capi part:
    bump2version --config-file .bumpversion-capi.cfg {{part}}
    cargo set-version --bump {{part}} -p abcrypt-capi
