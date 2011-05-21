CPPFLAGS = -DDEBUG -DLOG_LEVEL=LOG_DEBUG -I. -I.. -I../include
#CPPFLAGS = -I. -I.. -I../include
CFLAGS = -Wall -g

.PHONY: all clean

all: test

test: test.o test_sw_socket.o test_sw_bind.o test_sw_getsockname.o \
	test_sw_sendto.o test_sw_recvfrom.o \
	test_sw_sendmsg.o test_sw_recvmsg.o \
	test_sw_setsockopt.o test_sw_getsockopt.o \
	test_sw_close.o test_dummy.o
	../swift_raw.o ../swift_list.o

clean:
	-rm -f *~ *.o
	-rm -f test
