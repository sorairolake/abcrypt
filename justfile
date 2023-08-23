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

# Run the linter for GitHub Actions workflow files
@lint-github-actions:
    actionlint -verbose

# Run the formatter for the README
@fmt-readme:
    npx prettier -w README.md crate/*/README.md

# Build the book
build-book:
    #!/usr/bin/env bash
    cp asset/demo.gif {AUTHORS,BUILD,CHANGELOG,CONTRIBUTING}.adoc doc/book
    cp -r LICENSES doc/book
    mkdir -p doc/book/man
    cp doc/man/man1/*.1.adoc doc/book/man
    cp -r doc/man/include doc/book/man
    sed -i -E -e '/^:includedir:/s/\.//' -e '/ifdef::|endif::/d' doc/book/man/*.1.adoc
    npx honkit build

# Increment the version
@bump part:
    bump2version {{part}}
