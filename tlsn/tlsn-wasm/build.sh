#!/bin/bash
RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals" \
    cargo +nightly build --target wasm32-unknown-unknown -Z build-std=panic_abort,std
