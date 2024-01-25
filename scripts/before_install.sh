#!/bin/bash
#set -e

APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

if [ ! -d $APP_NAME ]; then
   mkdir ~/$APP_NAME
fi

#sleep 3

exit 0
