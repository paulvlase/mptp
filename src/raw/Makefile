CPPFLAGS = -DDEBUG -DLOG_LEVEL=LOG_DEBUG -I. -I.. -Iinclude
#CPPFLAGS = -I. -Iinclude
CFLAGS = -Wall -g

.PHONY: all clean

all: swift_raw_simple_test

swift_raw_simple_test: swift_raw_simple_test.o swift_raw.o socket_manager.o

swift_raw_simple_test.o: swift_raw_simple_test.c include/swift_raw.h include/util.h

swift_raw.o: swift_raw.c include/socket_manager.h include/swift_raw.h include/debug.h include/util.h

socket_manager.o: socket_manager.c include/socket_manager.h

clean:
	-rm -f *~
	-rm -f *.o
	-rm -f swift_raw_simple_test
