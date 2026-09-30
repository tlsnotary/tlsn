#!/bin/sh

# Builds the wasm package and checks the JS/TS contract that downstream
# consumers see. This is deliberately a consumer of `pkg/` (the artifact that
# gets published to npm), not of the Rust crate, so it catches regressions in
# the generated glue, the spawn.js snippet, and the .d.ts type surface.
#
# Usage:
#   ./test-package.sh              # build pkg/, then check it
#   ./test-package.sh --no-build   # check an existing pkg/

set -e

cd "$(dirname "$0")"

if [ "${1:-}" != "--no-build" ]; then
    ./build.sh
fi

if [ ! -f pkg/tlsn_wasm.js ] || [ ! -f pkg/tlsn_wasm.d.ts ]; then
    echo "Error: pkg/ is missing; run ./build.sh first"
    exit 1
fi

# build.sh must have patched and copied the spawn.js snippet into pkg/.
if [ ! -f pkg/spawn.js ]; then
    echo "Error: pkg/spawn.js missing (build.sh did not copy the snippet)"
    exit 1
fi
if ! grep -q 'tlsn_wasm.js' pkg/spawn.js; then
    echo "Error: pkg/spawn.js was not patched to import tlsn_wasm.js"
    exit 1
fi

# Type-level contract test against the generated .d.ts, plus a packaging
# check (entry points, files, module/type wiring) of pkg/package.json.
cd tests/contract
if [ -f package-lock.json ]; then
    npm ci
else
    npm install
fi
npx publint ../../pkg
npx tsc -p tsconfig.json

# Runtime smoke test: load the built package in a real browser and exercise
# the public API (construct, compute_reveal).
cd ../smoke
if [ -f package-lock.json ]; then
    npm ci
else
    npm install
fi
node smoke.mjs

echo "package checks OK"
