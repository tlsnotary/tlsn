#!/bin/sh

# This script is used to run checks before committing changes to the repository.
# It is a good approximation of what CI will do.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --all

# Check clippy
cargo clippy --all-features --all-targets -- -D warnings

# Build all targets
# cargo build --all-targets

# Run tests
# cargo test
