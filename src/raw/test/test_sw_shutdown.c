/*
 * Test sw_shutdown "syscall".
 */

#include "test_sw.h"
#include "test.h"

void shutdown_dummy(void)
{
	test(1 == 1);
}
