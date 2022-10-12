# Docker compose for instances of sysrepo-netopeer2 with cfgipsec2 support



The example is based on the following scenario:


					 		controller 
							netopeer-cli>   
							   (.200)  
								 |               
                  /-----------(10.0.1.0/24)------\
                 /                                \
                /                                  \
			   /                                    \
            (.204)									(.234)
	          h1 				                      h2
            (.100) ================ IPSEC========== (.200)
          				     (192.168.123.0/24) 


# Host-to-Host SAs ESP transport mode - Case 2 (IKEless case)

## Run the testbed:

`\# sudo ./up.sh`

## Check containers are running:

`\# docker-compose ps`


## Connect to the Netconf server 1 and launch the cfgipsec2 service:

`\# docker exec -it h2h_h1_1  /bin/bash`

`\# ./ietf-ipsec -c case2 -v 2`


## Connect to the Netconf server 2 and launch the cfgipsec2 service:

`\# docker exec -it h2h_h2_1 /bin/bash`

`\# ./ietf-ipsec -c case2 -v 2`


## Connect to the Netconf client for h1 configuration:

`\# docker exec -it h2h_c_1 /bin/bash`

`\# netopeer2-cli`


## Configure IPsec ESP host-2-host transport mode between h1

`>connect --host 10.0.1.204 --ssh --login netconf (password: netconf)`

`>subscribe`

(be sure there is not lifetime defined for SAs)

`>edit-config --target running --config=/home/netconf/cfgipsec2/client-xmls/case2/h2h_transport_esp_enc_auth_h1.xml`

`>get-config --source=running`


## Connect to the Netconf client for h2 configuration:

`\# docker exec -it h2h_c_1 /bin/bash`

`\# netopeer2-cli`


## Configure IPsec ESP host-2-host transport mode between h2


`>connect --host 10.0.1.234 --ssh --login netconf (password: netconf)`

`>subscribe`

`>edit-config --target running --config=/home/netconf/cfgipsec2/client-xmls/case2/h2h_transport_esp_enc_auth_h2.xml`

`>get-config --source=running`



## Test

If SAs expire apply configuration again from client.

Check SPD state in h1 and h2. For example, in h1:

`\# docker exec h2h_h1_1 ip -s x policy`

Check SAD state in h1 and h2. For example, in h1:

`\# docker exec h2h_h1_1 ip -s x state`

From h1, test ping to h2

`\# docker exec h2h_h1_1 ping 192.168.123.200`

Run tcpdump in h1 or h2

`\# docker exec h2h_h2_1 tcpdump -i eth1 esp`

(can take a while to show the ESP packets)


## Stop the testbed:

`\# sudo ./down.sh`


# Host-to-Host SAs ESP transport mode - Case 1 (IKE case)

## Run the testbed:

`\# sudo ./up.sh`

## Check containers are running:

`\# docker-compose ps`


## Connect to the Netconf server 1 and launch the cfgipsec2 service:

`\# docker exec -it h2h_h1_1  /bin/bash`

`\# ./ietf-ipsec -c case1 -v 2`


## Connect to the Netconf server 2 and launch the cfgipsec2 service:

`\# docker exec -it h2h_h2_1 /bin/bash`

`\# ./ietf-ipsec -c case1`


## Connect to the Netconf client:

`\# docker exec -it h2h_c_1 /bin/bash`

`\# netopeer2-cli`


## Configure IPsec ESP host-2-host transport mode between h1 and h2

`>connect --host 10.0.1.204 --ssh --login netconf (password: netconf)`

`>subscribe`

`>edit-config --target running --config=/home/netconf/cfgipsec2/client-xmls/case1/h2h_transport_esp_enc_auth_h1_spd_pad_ike.xml`


`>get-config --source=running`

`>disconnect`

`>connect --host 10.0.1.234 --ssh --login netconf (password: netconf)`

`>subscribe`

`>edit-config --target running --config=/home/netconf/cfgipsec2/client-xmls/case1/h2h_transport_esp_enc_auth_h2_spd_pad_ike.xml`


`>get-config --source=running`

`>disconnect`

## Test

Check SPD state in h1 and h2. For example, in h1:

`\# docker exec h2h_h1_1 swanctl -L`

From h1, test ping to h2

`\# docker exec h2h_h1_1 ping 192.168.123.200`

Run tcpdump in h1 or h2

`\# docker exec h2h_h2_1 tcpdump -i eth1 esp`

(can take a while to show the ESP packets)


## Stop the testbed:

`\# sudo ./down.sh`


















