#!/bin/bash
RUSTFLAGS="-C target-feature=+atomics,+bulk-memory,+mutable-globals" \
    rustup run nightly \
    wasm-pack test --headless --chrome \
    . -Z build-std=panic_abort,std
