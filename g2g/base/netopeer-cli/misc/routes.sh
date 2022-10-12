#!/bin/bash
if [ $HOSTNAME = "h1" ]; then
	echo "expression evaluated as true" > result.txt
	# h1 to gw1_gw2_data
	ip route add 192.168.123.0/24 via 192.168.201.2
	# h1 to gw2_data
	ip route add 192.168.202.0/24 via 192.168.201.2
fi
if [ $HOSTNAME = "h2" ]; then
	# h2 to g1_gw2_data
	ip route add 192.168.123.0/24 via 192.168.202.2
	# h2 to gw1_data
	ip route add 192.168.201.0/24 via 192.168.202.2
fi

#while true; do sleep 1; done

