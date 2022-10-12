FROM sysrepo/sysrepo-netopeer2:iop

ENV SRC_PATH /home/netconf
WORKDIR $SRC_PATH

RUN apt-get update
RUN apt-get install -y iproute2 tcpdump iputils-ping curl libpam0g-dev python-pip wget autotools-dev autoconf
RUN pip install ncclient
RUN pip install Flask
RUN pip install simplejson

RUN set -e -x; \
	wget https://iperf.fr/download/ubuntu/libiperf0_3.1.3-1_amd64.deb; \
	wget https://iperf.fr/download/ubuntu/iperf3_3.1.3-1_amd64.deb; \
	dpkg -i libiperf0_3.1.3-1_amd64.deb iperf3_3.1.3-1_amd64.deb;

#Install cfgipec2, not compilation required, only for xml configuration examples
RUN set -e -x; git clone https://gitlab.atica.um.es/gabilm.um.es/cfgipsec2;
	
	
RUN set -e -x; git clone https://gitlab.atica.um.es/gabilm.um.es/py-sc;	

ENV SRC_PATH /home/netconf/py-sc
WORKDIR $SRC_PATH

ARG case
ENV SDN_IPSEC_CASE=$case

ARG case2_mode
ENV SDN_IPSEC_CASE2_MODE=$case2_mode

COPY misc/supervisord.conf /etc/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

