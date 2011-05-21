/*
 * Test sw_recvfrom "syscall".
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

static void recvfrom_dummy(void);
static void recvfrom_invalid_descriptor(void);
static void recvfrom_descriptor_is_not_a_socket(void);
static void recvfrom_socket_is_not_bound(void);
static void recvfrom_after_sendto_ok(void);
static void recvfrom_after_sendmsg_ok(void);

void recvfrom_test_suite(void)
{
	start_suite();
	recvfrom_dummy();
}

static void recvfrom_dummy(void)
{
	test(1 == 1);
}

