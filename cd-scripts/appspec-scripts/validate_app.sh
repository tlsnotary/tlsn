#!/bin/bash
set -e

# Verify proccess is running
APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

# Verify that listening sockets exist
if [ $APP_NAME = "stable" ]; then
  PORT=$(curl http://169.254.169.254/latest/meta-data/tags/instance/port)
  ps -ef | grep notary.*$APP_NAME.*$PORT | grep -v grep
  [ $? -eq 0 ] || exit 1
else
  PORT=7048
  pgrep -f notary.*$APP_NAME
  [ $? -eq 0 ] || exit 1
fi

EXPOSED_PORTS=$(netstat -lnt4 | egrep -cw $PORT)
[ $EXPOSED_PORTS -eq 1 ] || exit 1

exit 0
