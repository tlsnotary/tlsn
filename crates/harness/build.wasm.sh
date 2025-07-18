#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

# A specific version of `wasm-pack` must be installed to build the WASM binary
cargo install --git https://github.com/rustwasm/wasm-pack.git --rev 32e52ca

rustup run nightly \
    wasm-pack build executor \
        --profile wasm \
        --target web \
        --out-dir=../static/generated \
        -- -Zbuild-std=panic_abort,std
