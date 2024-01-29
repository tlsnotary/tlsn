#!/bin/bash
set -e
export PATH=$PATH:/home/ubuntu/.cargo/bin

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

cd ~/$APP_NAME/tlsn/notary-server
target/release/notary-server --config-file ~/.notary/$APP_NAME/config.yaml &> ~/$APP_NAME/tlsn/notary.log &

exit 0
