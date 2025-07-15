#!/bin/sh

# This crate must be built using the nightly Rust compiler with specific flags.
# This script automates the build process.

set -e

# Clean up older builds
rm -rf pkg

# Build tlsn_wasm package
wasm-pack build \
    --profile wasm \
    --target web \
    .

# Patch tlsn_wasm.js import in spawn.js snippet and copy it to the main folder
file=$(find ./pkg/snippets -name "spawn.js" -print -quit)
if [ -z "$file" ]; then
    echo "Error: spawn.js snippet not found"
    find pkg
    exit 1
fi
temp=$(mktemp)
sed 's|../../..|../../../tlsn_wasm.js|' "$file" >"$temp" && mv "$temp" "$file"
cp ${file} ./pkg

# Add all files and snippets directory to package.json
file="pkg/package.json"
temp=$(mktemp)
jq '.files += ["tlsn_wasm_bg.wasm.d.ts"]' "$file" >"$temp" && mv "$temp" "$file"
jq '.files += ["spawn.js"]' "$file" >"$temp" && mv "$temp" "$file"
jq '.files += ["snippets/"]' "$file" >"$temp" && mv "$temp" "$file"
