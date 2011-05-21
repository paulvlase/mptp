/*
 * Test sw_close "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void close_dummy(void);
static void close_invalid_descriptor(void);
static void close_descriptor_is_not_a_socket(void);
static void close_ok_descriptor_is_bound(void);
static void close_ok_descriptor_is_not_bound(void);

void close_test_suite(void)
{
	start_suite();
	close_dummy();
}

static void close_dummy(void)
{
	test(1 == 1);
}

