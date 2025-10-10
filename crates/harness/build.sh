#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

RUNNER_FEATURES=""
EXECUTOR_FEATURES=""

if [ "$1" = "debug" ]; then
    RUNNER_FEATURES="--features debug"
    EXECUTOR_FEATURES="--no-default-features --features debug"
fi

cargo build --release \
    --package tlsn-harness-runner $RUNNER_FEATURES \
    --package tlsn-harness-executor $EXECUTOR_FEATURES \
    --package tlsn-server-fixture \
    --package tlsn-harness-plot

mkdir -p bin

cp ../../target/release/tlsn-harness-runner bin/runner
cp ../../target/release/tlsn-harness-executor-native bin/executor-native
cp ../../target/release/tlsn-server-fixture bin/server-fixture
cp ../../target/release/tlsn-harness-wasm-server bin/wasm-server
cp ../../target/release/tlsn-harness-plot bin/tlsn-harness-plot

./build.wasm.sh
