/*
 * Test sw_close "syscall".
 */

#include "test_sw.h"
#include "test.h"

void close_dummy(void)
{
	test(1 == 1);
}

