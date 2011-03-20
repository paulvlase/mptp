/*
 * Test sw_recvfrom "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void recvfrom_dummy(void);

void recvfrom_test_suite(void)
{
	start_suite();
	recvfrom_dummy();
}

static void recvfrom_dummy(void)
{
	test(1 == 1);
}

