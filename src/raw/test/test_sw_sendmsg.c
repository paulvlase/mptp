/*
 * Test sw_sendmsg "syscall".
 */

#include "test_sw.h"
#include "test.h"

void sendmsg_dummy(void)
{
	test(1 == 1);
}
