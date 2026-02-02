#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

# wasm-pack 0.14.0+ is required for custom profile support
cargo install wasm-pack

CARGO_FLAGS="-Zbuild-std=panic_abort,std"

if [ "$1" = "debug" ]; then
    # Disable default features to remove tracing/release_max_level_off
    CARGO_FLAGS="--no-default-features $CARGO_FLAGS"
fi

rustup run nightly \
    wasm-pack build executor \
        --profile wasm \
        --target web \
        --out-dir=../static/generated \
        -- $CARGO_FLAGS
