/*
 * Test sw_recvmsg "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void recvmsg_dummy(void);

void recvmsg_test_suite(void)
{
	start_suite();
	recvmsg_dummy();
}

static void recvmsg_dummy(void) 
{
	test(1 == 1);
}

