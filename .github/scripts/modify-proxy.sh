#!/bin/bash

set -e

GH_OWNER="ntampakas"
GH_REPO="tlsn"
BACKEND_INSTANCE_ID=$(aws ec2 describe-instances --filters Name=tag:Name,Values=[tlsnotary-backend-dev] --query "Reservations[*].Instances[*][InstanceId]" --output text)
PROXY_INSTANCE_ID=$(aws ec2 describe-instances --filters Name=tag:Name,Values=[tlsnotary-web] --query "Reservations[*].Instances[*][InstanceId]" --output text)
TAGS=$(aws ec2 describe-instances --instance-ids $BACKEND_INSTANCE_ID --query 'Reservations[*].Instances[*].Tags')

TAG=$(echo $TAGS | jq -r '.[][][] | select(.Key == "stable").Value')
PORT=$(echo $TAGS | jq -r '.[][][] | select(.Key == "port").Value')

COMMAND_ID=$(aws ssm send-command --document-name "AWS-RunRemoteScript" --instance-ids $PROXY_INSTANCE_ID --parameters '{"sourceType":["GitHub"],"sourceInfo":["{\"owner\":\"'${GH_OWNER}'\", \"repository\":\"'${GH_REPO}'\", \"getOptions\":\"branch:'${TAG}'\", \"path\": \"scripts\"}"],"commandLine":["modify_proxy.sh '${PORT}' '${TAG}' "]}' --output text --query "Command.CommandId")

while true; do
  SSM_STATUS=$(aws ssm list-command-invocations --command-id $COMMAND_ID --details --query "CommandInvocations[].Status" --output text)

  if [ $SSM_STATUS != "Success" ] && [ $SSM_STATUS != "InProgress" ]; then
    echo "Proxy modification failed"
    aws ssm list-command-invocations --command-id $COMMAND_ID --details --query "CommandInvocations[].CommandPlugins[].{Status:Status,Output:Output}"
    exit 1
  elif [ $SSM_STATUS = "Success" ]; then
    aws ssm list-command-invocations --command-id $COMMAND_ID --details --query "CommandInvocations[].CommandPlugins[].{Status:Status,Output:Output}"
    echo "Success"
    break
  fi

  sleep 2
done

exit 0
