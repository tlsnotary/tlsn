#!/bin/bash
set -e

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')
 
# Prepare directory
sudo rm -rf ~/$APP_NAME/tlsn
sudo mv ~/tlsn/ ~/$APP_NAME
sudo mkdir -p ~/$APP_NAME/tlsn/notary-server/target/release
sudo chown -R ubuntu.ubuntu ~/$APP_NAME
 
# Download .git directory
aws s3 cp s3://tlsn-deploy/$APP_NAME/.git ~/$APP_NAME/tlsn/.git --recursive

# Download binary
aws s3 cp s3://tlsn-deploy/$APP_NAME/notary-server ~/$APP_NAME/tlsn/notary-server/target/release
chmod +x ~/$APP_NAME/tlsn/notary-server/target/release/notary-server

exit 0
