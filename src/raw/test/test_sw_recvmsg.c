/*
 * Test sw_recvmsg "syscall".
 */

#include "test_sw.h"
#include "test.h"

void recvmsg_dummy(void)
{
	test(1 == 1);
}

