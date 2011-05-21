/*
 * Test sw_sendmsg "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void sendmsg_dummy(void);
static void sendmsg_invalid_descriptor(void);
static void sendmsg_descriptor_is_not_socket(void);
static void sendmsg_socket_is_not_bound(void);
static void sendmsg_ok(void);

void sendmsg_test_suite(void)
{
	start_suite();
	sendmsg_dummy();
}

static void sendmsg_dummy(void)
{
	test(1 == 1);
}
