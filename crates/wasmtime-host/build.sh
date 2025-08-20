#!/bin/bash

set -e

# Add ios targets (skip if already installed)
if ! rustup target list --installed | grep -q "aarch64-apple-ios-sim"; then
    rustup target add aarch64-apple-ios-sim
fi

if ! rustup target list --installed | grep -q "aarch64-apple-ios"; then
    rustup target add aarch64-apple-ios
fi

# Build the uniffi-bindgen binary and initial library file
cargo build

# Build FFI swift bindings
cargo run --bin uniffi-bindgen generate --library ../../target/debug/libwasmtime_host.a --language swift --out-dir ../../target/uniffi

# Rename binding for Xcode
mv ../../target/uniffi/wasmtime_hostFFI.modulemap ../../target/uniffi/module.modulemap

# Build ios binaries
cargo build --target aarch64-apple-ios-sim --release
cargo build --target aarch64-apple-ios --release

# Remove old XCFramework if it exists
if [ -d "../../target/ios/wasmtime_host.xcframework" ]; then
    rm -rf "../../target/ios/wasmtime_host.xcframework"
fi

# Build XCFramework required by Xcode
xcodebuild -create-xcframework \
    -library ../../target/aarch64-apple-ios-sim/release/libwasmtime_host.a -headers ../../target/uniffi \
    -library ../../target/aarch64-apple-ios/release/libwasmtime_host.a -headers ../../target/uniffi \
    -output "../../target/ios/wasmtime_host.xcframework"

echo -e "\033[32mBuild completed."

echo -e "\033[38;5;208mNow drag and drop 'wasmtime_host.xcframework/', 'uniffi/' into Xcode."
