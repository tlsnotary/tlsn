#!/bin/sh

rm -rf example.presentation.tlsn
RUST_LOG=debug cargo run --example attestation_present && RUST_LOG=debug cargo run --example attestation_verify
