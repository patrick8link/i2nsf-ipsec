FROM sysrepo/sysrepo-netopeer2:legacy

RUN cd /opt/dev && \
    cd libyang && git checkout v1.0.184 && \
    cd build && \ 
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE="Debug" -DENABLE_BUILD_TESTS=OFF .. && \
    make -j2 && make install

ENV SRC_PATH /home/netconf
WORKDIR $SRC_PATH

RUN apt-get update
RUN apt-get install -y iproute2 tcpdump iputils-ping curl libpam0g-dev autotools-dev autoconf
RUN apt-get install -y strongswan strongswan-swanctl

#Install strongswan
ARG STRONGSWAN_VERSION=5.5.0
ENV STRONGSWAN_VERSION_BUILD=$STRONGSWAN_VERSION

RUN set -e -x; \
      curl -O https://download.strongswan.org/strongswan-$STRONGSWAN_VERSION_BUILD.tar.bz2; \
      tar xvf strongswan* strongswan-5.5.0/src/libcharon/plugins/vici/libvici.h; 

RUN set -e -x; cp /home/netconf/strongswan-$STRONGSWAN_VERSION_BUILD/src/libcharon/plugins/vici/libvici.h /usr/local/include/;

ENV LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/ipsec:/usr/lib/ipsec/

#Install cfgipec2
RUN set -e -x; \
	git -c http.sslVerify=false clone https://gitlab.atica.um.es/gabilm.um.es/cfgipsec2.git; \
	cd cfgipsec2; 

ENV SRC_PATH /home/netconf/cfgipsec2
WORKDIR $SRC_PATH


COPY misc/supervisord.conf /etc/supervisord.conf
#CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]

#Debug
EXPOSE 830

#SSH
RUN apt update && apt install  openssh-server sudo -y
RUN useradd -rm -d /home/patrick -s /bin/bash -g root -G sudo -u 1000 patrick
RUN echo 'patrick:patrick' | chpasswd
RUN service ssh start
EXPOSE 22
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
