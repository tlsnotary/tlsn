#!/bin/bash
set -e

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

PID=$(pgrep -f notary.*$APP_NAME)
kill -15 $PID

exit 0
