#!/bin/sh

# This crate must be built using the nightly Rust compiler with specific flags.
# This script automates the build process.

set -e

# Clean up older builds
rm -rf pkg

# Build tlsn_wasm package
wasm-pack build --target web .

# Patch tlsn_wasm.js import in workerHelpers.worker.js
file=$(find ./pkg/snippets -name "workerHelpers.worker.js" -print -quit)
if [ -z "$file" ]; then
    echo "Error: workerHelpers.worker.js not found"
    find pkg
    exit 1
fi
temp=$(mktemp)
sed 's|../../../|../../../tlsn_wasm.js|' "$file" >"$temp" && mv "$temp" "$file"

# Add snippets directory to package.json
file="pkg/package.json"
temp=$(mktemp)
jq '.files += ["snippets/"]' "$file" >"$temp" && mv "$temp" "$file"
