#!/bin/bash
set -x

flag=0
control_network_ip=$(ip route | tail -2 | head -1 | awk '{print $9}')
data_network_ip=$(ip route | tail -1 | awk '{print $9}')

cfg="{\"control_network_ip\":\"$control_network_ip\",\"data_network_ip\":\"$data_network_ip\"}"

while [ $flag -eq 0 ]
do
	Response=$(curl --header "Content-Type: application/json" --data $cfg --request POST http://10.0.1.200:5000/register)
	
	echo $Response
	if [ $Response == "OK" ]
	then
		flag=1
	elif [ $Response == "ERROR" ]
	then
		flag=0
		sleep 3
	else
		flag=0
	fi
done
