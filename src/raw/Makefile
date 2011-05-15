CFLAGS = -Wall -g

.PHONY: all clean

all: swift_raw_simple_test

swift_raw_simple_test: swift_raw_simple_test.o swift_raw.o

swift_raw_simple_test.o: swift_raw_simple_test.c swift_raw.h util.h

swift_raw.o: swift_raw.c swift_raw.h

clean:
	-rm -f *~
	-rm -f *.o
	-rm -f swift_raw_simple_test
