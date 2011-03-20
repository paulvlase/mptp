/*
 * Test sw_sendto "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void sendto_dummy(void);

void sendto_test_suite(void)
{
	start_suite();
	sendto_dummy();
}

static void sendto_dummy(void)
{
	test(1 == 1);
}
