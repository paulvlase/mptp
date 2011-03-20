/*
 * Test sw_getsockname "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void getsockname_dummy(void);

void getsockname_test_suite(void)
{
	start_suite();
	getsockname_dummy();
}

static void getsockname_dummy(void)
{
	test(1 == 1);
}

