/*
 * Test sw_sendto "syscall".
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
