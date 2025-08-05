#!/bin/bash

PACKAGE_NAME="wasmtime_plugin"

set -e

# Build the project
cargo build --release

# Convert the wasm binary to a component
wasm-tools component new ../../target/wasm32-unknown-unknown/release/${PACKAGE_NAME}.wasm -o ../../target/wasm32-unknown-unknown/release/${PACKAGE_NAME}_component.wasm

echo "Component created: ${PACKAGE_NAME}_component.wasm"
