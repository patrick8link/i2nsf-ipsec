FROM sysrepo/sysrepo-netopeer2:iop

ENV SRC_PATH /home/netconf
WORKDIR $SRC_PATH

RUN apt-get update
RUN apt-get install -y iproute2 tcpdump iputils-ping supervisor curl libpam0g-dev wget autotools-dev autoconf
RUN apt-get install -y strongswan strongswan-swanctl

RUN set -e -x; \
	wget https://iperf.fr/download/ubuntu/libiperf0_3.1.3-1_amd64.deb; \
	wget https://iperf.fr/download/ubuntu/iperf3_3.1.3-1_amd64.deb; \
	dpkg -i libiperf0_3.1.3-1_amd64.deb iperf3_3.1.3-1_amd64.deb;

#Install strongswan
ARG STRONGSWAN_VERSION=5.5.0
ENV STRONGSWAN_VERSION_BUILD=$STRONGSWAN_VERSION


RUN set -e -x; \
      curl -O https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION_BUILD.tar.bz2; \
      tar xvf strongswan* strongswan-5.5.0/src/libcharon/plugins/vici/libvici.h; 

RUN set -e -x; cp /home/netconf/strongswan-$STRONGSWAN_VERSION_BUILD/src/libcharon/plugins/vici/libvici.h /usr/local/include/;


ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/ipsec:/usr/lib/ipsec/

ARG case
ENV SDN_IPSEC_CASE=$case

ARG case2_mode
ENV SDN_IPSEC_CASE2_MODE=$case2_mode

#Install cfgipec2
RUN set -e -x; \
	git clone https://gitlab.atica.um.es/gabilm.um.es/cfgipsec2.git; 

ENV SRC_PATH /home/netconf/cfgipsec2
WORKDIR $SRC_PATH

#RUN ipsec restart

COPY misc/netopeer-config.sh /etc/netopeer-config.sh
COPY misc/startup_ipsec.sh /home/netconf/startup_ipsec.sh

RUN chmod +x /etc/netopeer-config.sh
RUN chmod +x /home/netconf/startup_ipsec.sh

COPY misc/supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

#Debug
EXPOSE 830


