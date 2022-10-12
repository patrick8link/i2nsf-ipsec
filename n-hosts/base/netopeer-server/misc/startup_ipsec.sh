#!/bin/bash

if [ $SDN_IPSEC_CASE == "case1" ]; then
	/usr/sbin/ipsec restart
fi