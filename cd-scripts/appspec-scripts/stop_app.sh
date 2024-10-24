#!/bin/bash
# AWS CodeDeploy hook sequence: https://docs.aws.amazon.com/codedeploy/latest/userguide/reference-appspec-file-structure-hooks.html#appspec-hooks-server
set -ex

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

if [ $APP_NAME = "stable" ]; then
  VERSIONS_DEPLOYED=$(find ~/ -maxdepth 1 -type d -name 'stable_*')
  VERSIONS_DEPLOYED_COUNT=$(echo $VERSIONS_DEPLOYED | wc -w)

  # Remove oldest version if exists
  if [ $VERSIONS_DEPLOYED_COUNT -eq 3 ]; then
    echo "Candidate versions to be removed:"
    OLDEST_DIR=""
    OLDEST_TIME=""

    for DIR in $VERSIONS_DEPLOYED; do
      TIME=$(stat -c %W $DIR)

      if [ -z $OLDEST_TIME ] || [ $TIME -lt $OLDEST_TIME ]; then
        OLDEST_DIR=$DIR
        OLDEST_TIME=$TIME
      fi
    done

    echo "The oldest version is running under: $OLDEST_DIR"
    PID=$(lsof $OLDEST_DIR/tlsn/notary/target/release/notary-server | awk '{ print $2 }' | tail -1)
    kill -15 $PID || true
    rm -rf  $OLDEST_DIR
  fi
else
  PID=$(pgrep -f notary.*$APP_NAME)
  kill -15 $PID || true
fi

exit 0
