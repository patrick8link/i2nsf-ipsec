FROM sysrepo/sysrepo-netopeer2:legacy

ENV SRC_PATH /home/netconf
WORKDIR $SRC_PATH



RUN apt-get update
RUN apt-get install -y iproute2 tcpdump iputils-ping curl libpam0g-dev autotools-dev autoconf


#Install cfgipec2, not compilation required, only for xml configuration examples
RUN set -e -x; \
	git -c http.sslVerify=false clone https://gitlab.atica.um.es/gabilm.um.es/cfgipsec2.git; 

ENV SRC_PATH /home/netconf/cfgipsec2
WORKDIR $SRC_PATH



COPY misc/routes.sh .
#RUN chmod +x routes.sh
#ENTRYPOINT []
#CMD ["./routes.sh"]

COPY misc/supervisord.conf /etc/supervisord.conf
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]





