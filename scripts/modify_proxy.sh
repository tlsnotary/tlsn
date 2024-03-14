#!/bin/bash
set -e
 
PORT=$1
VERSION=$2
 
sed -i "/# Port $PORT/{n;s/v[0-9].[0-9].[0-9]-[a-z]*.[0-9]*/$VERSION/g}" /etc/nginx/sites-available/tlsnotary-pse
sed -i "/# Port $PORT/{n;n;s/v[0-9].[0-9].[0-9]-[a-z]*.[0-9]*/$VERSION/g}" /etc/nginx/sites-available/tlsnotary-pse
 
nginx -t
nginx -s reload
 
exit 0
