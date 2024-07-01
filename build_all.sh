#!/bin/bash

for package in components/cipher components/universal-hash components/aead components/key-exchange components/prf components/tls tlsn notary; do
    pushd $package
    # cargo update
    cargo clean
    cargo build
    cargo test
    cargo clippy --all-features --all-packages -- -D warnings || exit
    popd
done
