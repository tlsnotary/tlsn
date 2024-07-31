#!/bin/bash

for package in components/tls components/cipher components/universal-hash components/aead components/key-exchange components/prf tlsn notary; do
    pushd $package
    # cargo update
    cargo clean
    cargo clippy --all-features -- -D warnings || exit
    cargo build || exit
    cargo test || exit
    popd
done
