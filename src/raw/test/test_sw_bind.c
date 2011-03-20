/*
 * Test sw_bind "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void bind_dummy(void);

void bind_test_suite(void)
{
	start_suite();
	bind_dummy();
}

static void bind_dummy(void)
{
	test(1 == 1);
}
