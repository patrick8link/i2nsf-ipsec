# Docker compose for instances of netopeer1 with cfgipsec support

## Try it:

`# git clone https://gitlab.atica.um.es/gabilm.um.es/sysrepo-netopeer2-cfgipsec2.git `

`# cd sysrepo-netopeer2-cfgipsec2`


## Deploy the scenario:

`# cd n-hosts`

`# sudo ./up.sh n case mode` 

    where: 
		n: the number of instances of netopeers
		case: case1 (IKE case) or case2 (IKEless case)
		mode: only for case2: proactive or reactive


## Check containers are running:

`# docker-compose ps`

## Connect to the controller:
### MAC

`\# docker exec -it n-hosts_c_1 /bin/bash`

### Linux

`\# docker exec -it nhosts_c_1 /bin/bash`


## Check the netopeer SA:
### MAC

`# docker exec -it n-hosts_n_i /bin/bash`

### Linux

`# docker exec -it nhosts_n_i /bin/bash`


    where i is the number of the instance


## Check controller logs

`\# docker exec -it n-hosts_c_1 tail -f /home/netconf/py-sc/times.log`


## Ver SAD y SPD en netopeer

`ip xfrm policy`

`ip xfrm state`

## Capturar trafico en netopeer

`tcpdump -i eth1 esp`

## Ver la ip de datos en netopeer

`ip route | tail -1 | awk '{print $9}'`


## Limpiar las imagenes sucias en docker

`docker rmi $(docker images -f "dangling=true" -q)`
