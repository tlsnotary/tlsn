#!/bin/bash
set -e

# Verify proccess is running
APP_NAME=$(echo $APPLICATION_NAME | awk -F- '{ print $2 }')

pgrep -f notary.*$APP_NAME
[ $? -eq 0 ] || exit 1

# Verify that listening sockets exist
if [ "$APPLICATION_NAME" == "tlsn-nightly" ]; then
    port=7048
else
    port=7047
fi

exposed_ports=$(netstat -lnt4 | egrep -cw $port)
[ $exposed_ports -eq 1 ] || exit 1

exit 0
