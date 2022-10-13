#!/bin/bash



if [ $HOSTNAME = "gw1" ]; then
	# gw1 to gw2_data
	ip route add 192.168.202.0/24 via 192.168.123.200
fi

if [ $HOSTNAME = "gw2" ]; then
	# gw2 to gw1_dat
	ip route add 192.168.201.0/24 via 192.168.123.100
fi


