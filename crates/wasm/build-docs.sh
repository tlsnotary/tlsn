#!/usr/bin/env bash
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# List the packages you want to document
PACKAGES=("tlsn-core" "tlsn" "tlsn-wasm")

# Find all features, except for the "test" features
FEATURES=$(
    cargo metadata --no-deps --format-version=1 |
        jq -r --argjson names "$(printf '%s\n' "${PACKAGES[@]}" | jq -R . | jq -s .)" '
    .packages[]
    | select(.name as $n | $names | index($n))
    | .features
    | keys[]
    | select(. != "test" and . != "rstest")
  ' | sort -u | paste -sd, -
)

# Join package names for the `-p` args
PACKAGE_ARGS=()
for pkg in "${PACKAGES[@]}"; do
    PACKAGE_ARGS+=("-p" "$pkg")
done

# Build docs using the correct config and filtered features
cargo +nightly doc \
    "${PACKAGE_ARGS[@]}" \
    --no-deps \
    --features "$FEATURES"

# https://dev.to/deciduously/prepare-your-rust-api-docs-for-github-pages-2n5i
echo "Add index file -> tlsn"
echo "<meta http-equiv=\"refresh\" content=\"0; url=tlsn\">" >../../target/wasm32-unknown-unknown/doc/index.html
