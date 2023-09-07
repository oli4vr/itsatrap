NET_SNMP_VARS = $(shell net-snmp-config --netsnmp-libs --netsnmp-agent-libs --external-libs --external-agent-libs | xargs echo)
all:
	gcc -c inifind.c -o inifind.o -O3
	gcc -c sha512.c -o sha512.o -O3
	gcc -c encrypt.c -o encrypt.o -O3
	gcc -c entropy.c -o entropy.o -O3
	gcc -c tcpd.c -o tcpd.o -O3 -lpthread
	gcc itsatrap.c -o itsatrap -lpthread $(NET_SNMP_VARS) -O3 sha512.o encrypt.o entropy.o inifind.o tcpd.o
install:
	mkdir -p ~/bin 2>/dev/null
	cp itsatrap ~/bin/
bundle:
	rm -rf ~/.itsatrap
	./itsatrap -b main.csv
	./genpkg.sh
clean:
	rm *.o itsatrap pkg.tgz
uninstall:
	rm -rf ~/.itsatrap
	rm ~/bin/itsatrap
