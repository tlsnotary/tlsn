#!/bin/sh
set -e

# Clean up older builds
rm -rf pkg

# Build tlsn_wasm package
RUSTFLAGS='-C target-feature=+atomics,+bulk-memory,+mutable-globals' \
    rustup run nightly \
    wasm-pack build --target web . -- -Zbuild-std=panic_abort,std

# Patch tlsn_wasm.js import in workerHelpers.worker.js
file=$(ls ./pkg/snippets/wasm-bindgen-rayon-*/src/workerHelpers.worker.js)
temp=$(mktemp)
sed 's|../../../|../../../tlsn_wasm.js|' "$file" >"$temp" && mv "$temp" "$file"

# Add snippets directory to package.json
file="pkg/package.json"
temp=$(mktemp)
jq '.files += ["snippets/"]' "$file" >"$temp" && mv "$temp" "$file"
