#!/bin/bash
#set -e

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

if [ $APP_NAME = "nightly" ]; then
  if [ ! -d $APP_NAME ]; then
    mkdir ~/$APP_NAME
  fi
fi

exit 0
