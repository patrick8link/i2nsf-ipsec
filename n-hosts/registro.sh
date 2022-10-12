#!/bin/bash

sleep 20

containers=$(docker-compose ps | tail -n +4 | cut -d" " -f1 | sort -V)

for c in $containers
do 
	sleep 3
	docker exec -dt $c /etc/netopeer-config.sh
done
