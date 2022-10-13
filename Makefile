TARGET = ietf-i2nsf-ike

export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/ipsec/:/usr/lib/ipsec

CC = gcc
LIBS = -lsysrepo -lpthread -lcrypt  -lvici -L/usr/lib/ipsec/
CFLAGS = -Wall -w  -O3 -fPIC
DEPS = base/utils.h   		base/sysrepo_utils.h   		base/log.h   		base/spd_entry.h   		base/spa_entry.h   		base/pad_entry.h   		base/ikev2_entry.h   		base/pfkeyv2_entry.h
LDFLAGS = 
		

OBJ = $(TARGET).o \ base/utils.o 	base/sysrepo_utils.o 	base/log.o 	base/spd_entry.o 	base/sad_entry.o 	base/pad_entry.o 	base/ikev2_entry.o 	base/pfkeyv2_entry.o 


%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

$(TARGET) : $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) 
	rm -f *.o base/*.o *~ core

.PHONY: install

install:
	sysrepoctl --install --yang=./$(TARGET).yang --owner=root:root --permissions=666
	sysrepoctl --install --yang=./ietf-i2nsf-ikec.yang --owner=root:root --permissions=666

.PHONY: uninstall

uninstall:
	sysrepoctl --uninstall --module=$(TARGET)

.PHONY: clean

clean:
	rm -f *.o base/*.o *~ core 
