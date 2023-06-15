NET_SNMP_VARS = $(shell net-snmp-config --netsnmp-libs --netsnmp-agent-libs --external-libs --external-agent-libs | xargs echo)
all:
	gcc -c inifind.c -o inifind.o -O3
	gcc -c sha512.c -o sha512.o -O3
	gcc -c encrypt.c -o encrypt.o -O3
	gcc -c entropy.c -o entropy.o -O3
	gcc itsatrap.c -o itsatrap $(NET_SNMP_VARS) -O3 sha512.o encrypt.o entropy.o inifind.o
clean:
	rm *.o itsatrap