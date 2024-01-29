#!/bin/bash
set -e
export PATH=$PATH:/home/ubuntu/.cargo/bin

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')
BRANCH=$(curl http://169.254.169.254/latest/meta-data/tags/instance/$APP_NAME)
 
# Prepare directory
sudo rm -rf ~/$APP_NAME/tlsn
sudo mv ~/tlsn/ ~/$APP_NAME
sudo mkdir -p ~/$APP_NAME/tlsn/notary-server/target/release
sudo chown -R ubuntu.ubuntu ~/$APP_NAME
 
git clone -b $BRANCH --no-checkout https://github.com/ntampakas/tlsn.git /tmp/tlsn_remove
cp -rp /tmp/tlsn_remove/.git ~/$APP_NAME/tlsn
rm -rf /tmp/tlsn_remove

# Download binary
aws s3 cp s3://tlsn-deploy/$APP_NAME/notary-server ~/$APP_NAME/tlsn/notary-server/target/release
chmod +x ~/$APP_NAME/tlsn/notary-server/target/release/notary-server

exit 0
