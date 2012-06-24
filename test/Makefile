CC=gcc
CFLAGS=-g

build: client server client_udp server_udp client_lf server_lf client_time server_time

client: client.o

server: server.o

client_udp: client_udp.o

server_udp: server_udp.o

client_lf: client_lf.o

server_lf: server_lf.o

client_time: client_time.o

server_time: server_time.o

client.o: client.c

server.o: server.c

client_udp.o: client_udp.c

server_udp.o: server_udp.c

client_lf.o: client_lf.c

server_lf.o: server_lf.c

client_time.o: client_time.c

server_time.o: server_time.c

clean:
	rm -f *.o *~ client server client_udp server_udp client_lf server_lf client_time server_time
