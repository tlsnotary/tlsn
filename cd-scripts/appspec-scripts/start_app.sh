#!/bin/bash
# Port tagging will also be used to manipulate proxy server via modify_proxy.sh script
set -ex

TAG=$(curl http://169.254.169.254/latest/meta-data/tags/instance/stable)
APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

if [ $APP_NAME = "stable" ]; then
  # Check if all stable ports are in use. If true, terminate the deployment
  [[ $(netstat -lnt4 | egrep -c ':(7047|7057|7067)\s') -eq 3 ]] && { echo "All stable ports are in use"; exit 1; }
  STABLE_PORTS="7047 7057 7067"
  for PORT in $STABLE_PORTS; do
    PORT_LISTENING=$(netstat -lnt4 | egrep -cw $PORT || true)
    if [ $PORT_LISTENING -eq 0 ]; then
      ~/${APP_NAME}_${TAG}/tlsn/notary/target/release/notary-server --config-file ~/.notary/${APP_NAME}_${PORT}/config.yaml &> ~/${APP_NAME}_${TAG}/tlsn/notary.log &
      # Create a tag that will be used for service validation
      INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
      aws ec2 create-tags --resources $INSTANCE_ID --tags "Key=port,Value=$PORT"
    break
    fi
  done
else
  ~/$APP_NAME/tlsn/notary/target/release/notary-server --config-file ~/.notary/$APP_NAME/config.yaml &> ~/$APP_NAME/tlsn/notary.log &
fi

exit 0
