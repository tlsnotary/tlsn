#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

cargo build --release --package tlsn-harness-runner --package tlsn-harness-executor --package tlsn-server-fixture

mkdir -p bin

cp ../../target/release/tlsn-harness-runner bin/runner
cp ../../target/release/tlsn-harness-executor-native bin/executor-native
cp ../../target/release/tlsn-server-fixture bin/server-fixture
cp ../../target/release/tlsn-harness-wasm-server bin/wasm-server

./build.wasm.sh
