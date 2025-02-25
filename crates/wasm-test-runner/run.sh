#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals -C link-arg=--max-memory=4294967296' \
    rustup run nightly \
    wasm-pack build ../wasm --target web --no-pack --out-dir=../wasm-test-runner/static/generated -- -Zbuild-std=panic_abort,std --features test &&
    RUST_LOG=info cargo run --release
