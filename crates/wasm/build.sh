#!/bin/sh

# This crate must be built using the nightly Rust compiler with specific flags.
# This script automates the build process.

set -e

# Check wasm-pack version (0.14.0+ required for custom profile support)
if ! command -v wasm-pack >/dev/null 2>&1; then
    echo "Error: wasm-pack not found. Install with: cargo install wasm-pack"
    exit 1
fi
WASM_PACK_VERSION=$(wasm-pack --version | sed 's/wasm-pack //')
REQUIRED_VERSION="0.14.0"
if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$WASM_PACK_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
    echo "Error: wasm-pack $WASM_PACK_VERSION is too old. Version $REQUIRED_VERSION+ required."
    echo "Install with: cargo install wasm-pack"
    exit 1
fi

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
