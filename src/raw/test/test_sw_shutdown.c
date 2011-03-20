/*
 * Test sw_shutdown "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void shutdown_dummy(void);

void shutdown_test_suite(void)
{
	start_suite();
	shutdown_dummy();
}

static void shutdown_dummy(void) 
{
	test(1 == 1);
}	
