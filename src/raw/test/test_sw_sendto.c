/*
 * Test sw_sendto "syscall".
 */

#include "test_sw.h"
#include "test.h"

static void sendto_dummy(void);
static void sendto_invalid_descriptor(void);
static void sendto_descriptor_is_not_socket(void);
static void sendto_socket_is_not_bound(void);
static void sendto_ok(void);

void sendto_test_suite(void)
{
	start_suite();
	sendto_dummy();
}

static void sendto_dummy(void)
{
	test(1 == 1);
}
