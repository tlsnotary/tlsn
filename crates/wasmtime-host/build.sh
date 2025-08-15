#!/bin/bash

set -e

# Build the crate to target aarch-linux-android
cargo ndk -t arm64-v8a build --release

# Build FFI kotlin bindings
cargo run --bin uniffi-bindgen generate --library ../../target/aarch64-linux-android/release/libwasmtime_host.so --language kotlin --out-dir ../../target

# Copy binary to android development environment (assumes androidwasmtime repo is present)
cp ../../target/aarch64-linux-android/release/libwasmtime_host.so ../../../androidwasmtime/app/src/main/jniLibs/arm64-v8a/

# Copy kotlin bindings to android development environment
cp ../../target/uniffi/wasmtime_host/wasmtime_host.kt ../../../androidwasmtime/app/src/main/java/uniffi/wasmtime/

echo "Binary and bindings copied to android dev env"
