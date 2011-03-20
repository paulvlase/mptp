/*
 * Test sw_socket "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void socket_dummy(void);

void socket_test_suite(void)
{
	start_suite();
	socket_dummy();
}

static void socket_dummy(void)
{
	test(1 == 1);
}
