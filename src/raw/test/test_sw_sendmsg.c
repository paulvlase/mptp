/*
 * Test sw_sendmsg "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void sendmsg_dummy(void);

void sendmsg_test_suite(void)
{
	start_suite();
	sendmsg_dummy();
}

static void sendmsg_dummy(void)
{
	test(1 == 1);
}
