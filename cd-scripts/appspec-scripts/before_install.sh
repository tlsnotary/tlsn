#!/bin/bash
set -e

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

if [ $APP_NAME = "stable" ]; then
  VERSIONS_DEPLOYED=$(find ~/ -maxdepth 1 -type d -name 'stable_*')
  VERSIONS_DEPLOYED_COUNT=$(echo $VERSIONS_DEPLOYED | wc -w)

  if [ $VERSIONS_DEPLOYED_COUNT -gt 3 ]; then
    echo "More than 3 stable versions found"
    exit 1
  fi
else
  if [ ! -d ~/$APP_NAME ]; then
    mkdir ~/$APP_NAME
  fi
fi

exit 0
