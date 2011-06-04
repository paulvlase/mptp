CPPFLAGS = -DDEBUG -DLOG_LEVEL=LOG_DEBUG -I. -I.. -I../include
#CPPFLAGS = -I. -I.. -I../include
CFLAGS = -Wall -g

.PHONY: all clean

all: test

test: test.o test_sw_socket.o test_sw_bind.o test_sw_getsockname.o \
	test_sw_sendto.o test_sw_recvfrom.o \
	test_sw_sendmsg.o test_sw_recvmsg.o \
	test_sw_setsockopt.o test_sw_getsockopt.o \
	test_sw_close.o test_dummy.o test_common.o \
	../swift_raw.o ../swift_list.o

../swift_raw.o: ../swift_raw.c ../include/swift_raw.h
	make -C .. swift_raw.o

../swift_list.o: ../swift_list.c ../include/swift_list.h
	make -C .. swift_list.o

clean:
	-rm -f *~ *.o
	-rm -f test
