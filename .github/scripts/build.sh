#!/bin/bash
set -ex

environment=$1

cd notary-server
cargo build --release
aws s3 cp target/release/notary-server s3://tlsn-deploy/$environment/

exit 0
