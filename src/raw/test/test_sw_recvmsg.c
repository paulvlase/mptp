/*
 * Test sw_recvmsg "syscall".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "swift_raw.h"
#include "swift_types.h"

#include "debug.h"
#include "util.h"

#include "test_sw.h"
#include "test.h"

static void recvmsg_dummy(void);
static void recvmsg_invalid_descriptor(void);
static void recvmsg_descriptor_is_not_a_socket(void);
static void recvmsg_socket_is_not_bound(void);
static void recvmsg_after_sendto_ok(void);
static void recvmsg_after_sendmsg_ok(void);

void recvmsg_test_suite(void)
{
	start_suite();
	recvmsg_dummy();

	recvmsg_invalid_descriptor();
	recvmsg_descriptor_is_not_a_socket();
	recvmsg_socket_is_not_bound();
	recvmsg_after_sendto_ok();
	recvmsg_after_sendmsg_ok();
}

static void recvmsg_dummy(void) 
{
	test(1 == 1);
}

static void recvmsg_invalid_descriptor(void)
{
	test (1 == 0);
}
static void recvmsg_descriptor_is_not_a_socket(void)
{
	test (1 == 0);
}
static void recvmsg_socket_is_not_bound(void)
{
	test (1 == 0);
}
static void recvmsg_after_sendto_ok(void)
{
	test (1 == 0);
}
static void recvmsg_after_sendmsg_ok(void)
{
	test (1 == 0);
}
