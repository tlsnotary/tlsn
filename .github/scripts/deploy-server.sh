#!/bin/bash
set -ex

environment=$1
branch=$2

INSTANCE_ID=$(aws ec2 describe-instances --filters Name=tag:Name,Values=[tlsnotary-backend-v1] Name=instance-state-name,Values=[running] --query "Reservations[*].Instances[*][InstanceId]" --output text)
aws ec2 create-tags --resources $INSTANCE_ID --tags "Key=$environment,Value=$branch"

COMMIT_HASH=$(git rev-parse HEAD)
DEPLOY_ID=$(aws deploy create-deployment --application-name tlsn-$environment-v1 --deployment-group-name tlsn-$environment-v1-group --github-location repository=$GITHUB_REPOSITORY,commitId=$COMMIT_HASH --ignore-application-stop-failures --file-exists OVERWRITE --output text)

while true; do
  STATUS=$(aws deploy get-deployment --deployment-id $DEPLOY_ID --query 'deploymentInfo.status' --output text)
  if [ $STATUS != "InProgress" ] && [ $STATUS != "Created" ]; then
    if [ $STATUS = "Succeeded" ]; then
       echo "SUCCESS"
       exit 0
    else
       echo "Failed"
       exit 1
    fi
  else
    echo "Deploying..."
  fi
     sleep 30
done
