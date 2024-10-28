#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
    rustup run nightly \
    wasm-pack build ../wasm --target web --no-pack --out-dir=../wasm-test-runner/static/generated -- -Zbuild-std=panic_abort,std --features test,no-bundler &&
    RUST_LOG=debug cargo run --release
