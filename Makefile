CC=gcc
CFLAGS = -g -O2 -Wall
PROG=ping_server ping_client

all:: $(PROG)

install: $(PROG)
	install ping_server /usr/local/bin
	[ -e /usr/libexec/check_icmp_daemon ] && mv /usr/libexec/check_icmp_daemon /usr/libexec/check_icmp_daemon.old
	cp ping_client /usr/libexec/check_icmp_daemon

ping_client: ping_client.c
	$(CC) -o $@ $(CFLAGS) $<

ping_server: ping_server.c 
	$(CC) -o $@ $(CFLAGS) $< -lrt

clean::
	-rm $(PROG)
