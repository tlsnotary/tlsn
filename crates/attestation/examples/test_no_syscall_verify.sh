#!/bin/bash
# Test that presentation verification works without getrandom syscalls.
#
# This script:
# 1. Builds prover with normal getrandom (needs RNG for creating attestation)
# 2. Builds verifier with getrandom_backend="unsupported" (no syscalls)
# 3. Runs both and verifies they communicate successfully

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$CRATE_DIR"

echo "=== Building prover (normal getrandom) ==="
cargo build --example prover_tcp --features fixtures

echo ""
echo "=== Building verifier (getrandom_backend=unsupported) ==="
RUSTFLAGS='--cfg getrandom_backend="unsupported"' cargo build --example verifier_tcp --features fixtures

echo ""
echo "=== Running test ==="

# Start prover in background
../../target/debug/examples/prover_tcp &
PROVER_PID=$!

# Give prover time to start listening
sleep 1

# Run verifier
../../target/debug/examples/verifier_tcp
VERIFIER_EXIT=$?

# Clean up
kill $PROVER_PID 2>/dev/null || true

if [ $VERIFIER_EXIT -eq 0 ]; then
    echo ""
    echo "=== TEST PASSED ==="
    echo "Presentation verification works without getrandom syscalls!"
    exit 0
else
    echo ""
    echo "=== TEST FAILED ==="
    exit 1
fi
