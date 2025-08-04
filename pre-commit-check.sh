#!/bin/sh

# This script is used to run checks before committing changes to the repository.
# It is a good approximation of what CI will do.

# Fail if any command fails
set -e

# Check formatting
cargo +nightly fmt --check --all

# Check clippy
cargo clippy --all-features --all-targets --locked -- -D warnings

# Build all targets
cargo build --all-targets --locked

# Run tests
cargo test --locked

# Run integration tests, excluding specific targets
cargo test --locked --profile tests-integration --workspace --exclude tlsn-tls-client --exclude tlsn-tls-core -- --include-ignored
