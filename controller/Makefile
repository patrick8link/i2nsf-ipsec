TARGET = ietf-i2nsf-controller

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/ipsec/:/usr/lib/ipsec

CC = gcc
LIBS = -lsysrepo -lpthread -lcrypt -L/usr/lib/ipsec/ -lnetconf2
CFLAGS = -Wall -w  -O3 -fPIC
DEPS = ../control_base/utils.h   		../control_base/sysrepo_utils.h   		../control_base/log.h
LDFLAGS = 
		

OBJ = $(TARGET).o \ ../control_base/utils.o 	../control_base/sysrepo_utils.o 	../control_base/log.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET) : $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) 
	rm -f *.o ../control_base/*.o *~ core

.PHONY: install

install:
	sysrepoctl --install --yang=../ietf-i2nsf-ike.yang --owner=root:root --permissions=666
	sysrepoctl --install --yang=../ietf-i2nsf-ikec.yang --owner=root:root --permissions=666

.PHONY: uninstall

uninstall:
	sysrepoctl --uninstall --module=$(TARGET)

.PHONY: clean

clean:
	rm -f *.o ../control_base/*.o *~ core 