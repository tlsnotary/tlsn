#!/bin/bash
set -e

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

cd ~/$APP_NAME/tlsn/notary-server
target/release/notary-server --config-file ~/.notary/$APP_NAME/config.yaml &> ~/$APP_NAME/tlsn/notary.log &

exit 0
