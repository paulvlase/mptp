/*
 * Test sw_close "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void close_dummy(void);

void close_test_suite(void)
{
	start_suite();
	close_dummy();
}

static void close_dummy(void)
{
	test(1 == 1);
}

