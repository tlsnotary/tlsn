#!/bin/bash
set -x

TAG=$(curl http://169.254.169.254/latest/meta-data/tags/instance/stable)
APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

if [ $APP_NAME = "stable" ]; then
  STABLE_PORTS="7047 7057 7067"
  for PORT in $STABLE_PORTS; do
    PORT_LISTENING=$(netstat -lnt4 | egrep -cw $PORT)
    if [ $PORT_LISTENING -eq 0 ]; then
      cd ~/${APP_NAME}_${TAG}/tlsn/notary-server
      target/release/notary-server --config-file ~/.notary/${APP_NAME}_${PORT}/config.yaml &> ~/${APP_NAME}_${TAG}/tlsn/notary.log &
      # Create a tag that will be used for service validation
      INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
      aws ec2 create-tags --resources $INSTANCE_ID --tags "Key=port,Value=$PORT"
    break
    fi
  done
else
  cd ~/$APP_NAME/tlsn/notary-server
  target/release/notary-server --config-file ~/.notary/$APP_NAME/config.yaml &> ~/$APP_NAME/tlsn/notary.log &
fi

exit 0
