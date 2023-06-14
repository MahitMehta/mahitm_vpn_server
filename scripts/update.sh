#!/bin/bash

sudo -i

cd mahitm_vpn_server

docker compose -f docker-compose.yml -f production.yml pull

docker compose -f docker-compose.yml -f production.yml up
