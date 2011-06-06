CPPFLAGS = -DDEBUG -DLOG_LEVEL=LOG_DEBUG -I. -I.. -Iinclude
#CPPFLAGS = -I. -I.. -I
CFLAGS = -Wall -g

.PHONY: all clean

all: test

test: test.o test_socket.o test_bind.o test_getsockname.o \
	test_sendto.o test_recvfrom.o \
	test_sendmsg.o test_recvmsg.o \
	test_setsockopt.o test_getsockopt.o \
	test_close.o test_dummy.o test_common.o 


clean:
	-rm -f *~ *.o
	-rm -f test
