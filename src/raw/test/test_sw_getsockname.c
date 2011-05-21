/*
 * Test sw_getsockname "syscall".
 */

#include "test_sw.h"
#include "test.h"

void getsockname_dummy(void)
{
	test(1 == 1);
}

