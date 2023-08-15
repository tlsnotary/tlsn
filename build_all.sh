#!/bin/bash

for package in components/uid-mux components/actors/actor-ot components/cipher components/universal-hash components/aead components/key-exchange components/point-addition components/prf components/tls tlsn; do
    pushd $package
    # cargo update
    cargo clean
    cargo build
    cargo test
    cargo clippy --all-features -- -D warnings || exit
    popd
done
