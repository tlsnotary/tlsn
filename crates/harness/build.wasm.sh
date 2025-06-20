#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

rustup run nightly \
    wasm-pack build executor --target web --no-pack --out-dir=../static/generated -- -Zbuild-std=panic_abort,std