/*
 * Test sw_recvmsg "syscall".
 */

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
}

static void recvmsg_dummy(void) 
{
	test(1 == 1);
}

