#!/bin/sh

# This crate must be built using the nightly Rust compiler with specific flags.
# This script automates the build process.

set -e

# Clean up older builds
rm -rf pkg

# Build tlsn_wasm package
wasm-pack build --target web .

