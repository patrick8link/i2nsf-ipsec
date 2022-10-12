# Docker compose for instances of sysrepo-netopeer2 with cfgipsec2 support


This docker compose feeds from [Dockerfile for sysrepo-netopeer2](https://github.com/sysrepo-archive/docker-sysrepo-netopeer2) and from [cfgipsec: IPsec SAs configuration](https://gitlab.atica.um.es/gabilm.um.es/cfgipsec2).

## Scenarios:

- Gw-2-Gw SA with ESP in tunnel mode (case 1 and case 2). Set up a basic gateway to gateway scenario with manual controller. 

- Host-2-Host SA with ESP in transport mode (case 1 and case 2). Set up a basic host to host scenario with manual controller. 

- N Host SA with ESP in transport mode: Set up a NxN host to host scenario dynamically managed by a python-based controller. 


## Try it:

To test the different scenarios:

`# git clone https://gitlab.atica.um.es/gabilm.um.es/sysrepo-netopeer2-cfgipsec2.git `

`# cd sysrepo-netopeer2-cfgipsec2`

`# cd scenario_name`

Follow the README.md instructions.





 




















