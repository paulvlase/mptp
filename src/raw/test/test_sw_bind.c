/*
 * Test sw_bind "syscall".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "swift_raw.h"
#include "swift_types.h"

#include "debug.h"
#include "util.h"

#include "test_sw.h"
#include "test.h"

static void bind_dummy(void);
static void bind_invalid_descriptor(void);
static void bind_descriptor_not_a_socket(void);
static void bind_invalid_ip_address(void);
static void bind_address_in_use(void);
static void bind_socket_already_bound(void);
static void bind_ok(void);

void bind_test_suite(void)
{
	start_suite();
	bind_dummy();
}

static void bind_dummy(void)
{
	test(1 == 1);
}
