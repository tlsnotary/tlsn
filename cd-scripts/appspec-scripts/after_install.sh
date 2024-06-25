#!/bin/bash
set -e

TAG=$(curl http://169.254.169.254/latest/meta-data/tags/instance/stable)
APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')
 
if [ $APP_NAME = "stable" ]; then
  # Prepare directories for stable versions
  sudo mkdir ~/${APP_NAME}_${TAG}
  sudo mv ~/tlsn ~/${APP_NAME}_${TAG}
  sudo mkdir -p ~/${APP_NAME}_${TAG}/tlsn/notary/target/release
  sudo chown -R ubuntu.ubuntu ~/${APP_NAME}_${TAG}

  # Download .git directory
  aws s3 cp s3://tlsn-deploy/$APP_NAME/.git ~/${APP_NAME}_${TAG}/tlsn/.git --recursive

  # Download binary
  aws s3 cp s3://tlsn-deploy/$APP_NAME/notary-server ~/${APP_NAME}_${TAG}/tlsn/notary/target/release
  chmod +x ~/${APP_NAME}_${TAG}/tlsn/notary/target/release/notary-server
else
  # Prepare directory for dev
  sudo rm -rf ~/$APP_NAME/tlsn
  sudo mv ~/tlsn/ ~/$APP_NAME
  sudo mkdir -p ~/$APP_NAME/tlsn/notary/target/release
  sudo chown -R ubuntu.ubuntu ~/$APP_NAME
   
  # Download .git directory
  aws s3 cp s3://tlsn-deploy/$APP_NAME/.git ~/$APP_NAME/tlsn/.git --recursive
  
  # Download binary
  aws s3 cp s3://tlsn-deploy/$APP_NAME/notary-server ~/$APP_NAME/tlsn/notary/target/release
  chmod +x ~/$APP_NAME/tlsn/notary/target/release/notary-server
fi

exit 0
