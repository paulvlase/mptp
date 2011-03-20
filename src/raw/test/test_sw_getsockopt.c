/*
 * Test sw_getsockopt "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void getsockopt_dummy(void);

void getsockopt_test_suite(void)
{
	start_suite();
	getsockopt_dummy();
}

static void getsockopt_dummy(void)
{
	test(1 == 1);
}

