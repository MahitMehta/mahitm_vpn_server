#!/bin/bash

sudo su - <<EOF

pwd 

cd mahitm_vpn_server

git pull origin master

docker compose -f docker-compose.yml -f production.yml up --detach

EOF