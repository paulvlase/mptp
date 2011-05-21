/*
 * Test sw_bind "syscall".
 */

#include "test_sw.h"
#include "test.h"

void bind_dummy(void)
{
	test(1 == 1);
}
