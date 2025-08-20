#!/bin/bash

PACKAGE_NAME="wasmtime_plugin"

set -e

# Build the project
cargo build --release

# Convert the wasm binary to a component
wasm-tools component new ../../target/wasm32-unknown-unknown/release/${PACKAGE_NAME}.wasm -o ../../target/wasm32-unknown-unknown/release/${PACKAGE_NAME}_component.wasm

echo -e "\033[32mComponent created: ${PACKAGE_NAME}_component.wasm.\033[0m"

echo -e "\033[38;5;208mNow drag and drop it into Xcode.\033[0m"
