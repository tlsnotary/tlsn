#!/bin/bash
# https://github.com/tlsnotary/tlsn/pull/419
set -ex

environment=$1

aws s3 sync .git s3://tlsn-deploy/$environment/.git --delete

cargo build -p notary-server --release
aws s3 cp ./target/release/notary-server s3://tlsn-deploy/$environment/

exit 0
