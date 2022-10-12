#!/bin/bash

#$1 = number of nodes
#$2 = ikeless or ike

n=$1
case=$2
case2_mode=$3

if [[ -z $case ]] || [[ -z $n ]]; then
  echo "wrong input: ./up.sh nodes case [ mode ]"
  echo "nodes: number of nodes"
  echo "case: case1 or case2"
  echo "mode: only for case2: reactive or proactive"
  exit 0
fi

if [[ -z $case ]]; then
  echo "case is empty: case1 or case2"
  exit 0
fi

if [[ $case = "case2" ]]; then
	
	if [[ $case2_mode = "proactive" ]]; then
			echo "IKE-less proactive case starting..."
	elif [[ $case2_mode = "reactive" ]]; then
		echo "IKE-less reactive case starting..."
	else
		echo "Wrong mode for case 2: it must be proactive reactive"
		exit 0
	fi
	
elif [[ $case = "case1" ]]; then
	echo "IKE case starting..."
else
	echo "Wrong parameter: it must be case1 or case2"
	exit 0
fi

#if [[ -z $1 ]] || ( ! [[ $1 =~ ^[0-9]+$ ]] && [[ $1 -gt 0 ]] ); then
#	docker-compose up -d --build
#else

	echo Deploy with $1 instances
	sleep 0.5
	docker-compose build --build-arg case=$case --build-arg case2_mode=$case2_mode

	docker-compose up -d --scale n=$n
	#fi

#After set up all the nodes, they are going to sign up in the controller
./registro.sh
