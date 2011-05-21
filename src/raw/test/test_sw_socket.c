/*
 * Test sw_socket "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void socket_dummy(void);
static void socket_invalid_domain(void);
static void socket_invalid_type(void);
static void socket_invalid_protocol(void);
static void socket_insufficient_file_descriptors(void);
static void socket_ok(void);

void socket_test_suite(void)
{
	start_suite();
	socket_dummy();
}

/* Dummy function for testing purposes only. */
static void socket_dummy(void)
{
	test(1 == 1);
}
