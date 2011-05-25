CPPFLAGS = -DDEBUG -DLOG_LEVEL=LOG_DEBUG -I. -I.. -I../include
#CPPFLAGS = -I. -Iinclude
CFLAGS = -Wall -g

.PHONY: all clean

all: swift_raw_simple_test

swift_raw_simple_test: swift_raw_simple_test.o swift_raw.o swift_list.o

swift_raw_simple_test.o: swift_raw_simple_test.c include/swift_raw.h include/util.h

swift_raw.o: swift_raw.c include/swift_list.h include/swift_raw.h include/debug.h include/util.h

swift_list.o: swift_list.c include/swift_list.h

clean:
	-rm -f *~
	-rm -f *.o
	-rm -f swift_raw_simple_test
