#!/bin/sh

# Ensure the script runs in the folder that contains this script
cd "$(dirname "$0")"

cargo build --package tlsn-harness-runner

mkdir -p bin

cp ../../target/debug/tlsn-harness-runner bin/runner