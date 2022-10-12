FROM sysrepo/sysrepo-netopeer2:legacy

ENV SRC_PATH /home/netconf
WORKDIR $SRC_PATH

RUN cd /opt/dev && \
    cd libyang && git checkout v1.0.184 && \
    cd build && \ 
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE="Debug" -DENABLE_BUILD_TESTS=OFF .. && \
    make -j2 && make install

RUN apt-get update
RUN apt-get install -y iproute2 tcpdump iputils-ping curl libpam0g-dev autotools-dev autoconf
RUN apt-get install -y strongswan strongswan-swanctl

#Install strongswan libvici.h
ARG STRONGSWAN_VERSION=5.5.0
ENV STRONGSWAN_VERSION_BUILD=$STRONGSWAN_VERSION


RUN set -e -x; \
      curl -O https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION_BUILD.tar.bz2; \
      tar xvf strongswan* strongswan-5.5.0/src/libcharon/plugins/vici/libvici.h; 

RUN set -e -x; cp /home/netconf/strongswan-$STRONGSWAN_VERSION_BUILD/src/libcharon/plugins/vici/libvici.h /usr/local/include/;

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/ipsec:/usr/lib/ipsec/

RUN set -e -x; \
	git -c http.sslVerify=false clone https://gitlab.atica.um.es/gabilm.um.es/cfgipsec2.git; \
	cd cfgipsec2; 


ENV SRC_PATH /home/netconf/cfgipsec2
WORKDIR $SRC_PATH

COPY misc/routes.sh .


COPY misc/supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

#Debug
EXPOSE 830



