CFLAGS = -g -Wall -fPIC
LDFLAGS = -L.
LDLIBS = -lswift

.PHONY: all clean

all: server client

client: client.o libswift.so

server: server.o libswift.so

client.o: client.c lib_swift.h

server.o: server.c lib_swift.h

libswift.so: lib_swift.o
	$(CC) -shared -o $@ $^

lib_swift.o: lib_swift.c lib_swift.h

clean:
	-rm -f server client libswift.so
	-rm -f *.o
	-rm -f *~
