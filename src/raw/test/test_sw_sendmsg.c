/*
 * Test sw_sendmsg "syscall".
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

static void sendmsg_dummy(void);
static void sendmsg_invalid_descriptor(void);
static void sendmsg_descriptor_is_not_socket(void);
static void sendmsg_socket_is_not_bound(void);
static void sendmsg_ok(void);

void sendmsg_test_suite(void)
{
	start_suite();
	sendmsg_dummy();
	sendmsg_invalid_descriptor();
	sendmsg_descriptor_is_not_socket();
	sendmsg_socket_is_not_bound();
	sendmsg_ok();
}

static void sendmsg_dummy(void)
{
	test (1 == 1);
}

static void sendmsg_invalid_descriptor(void)
{
	test (1 == 0);
}

static void sendmsg_descriptor_is_not_socket(void)
{
	test (1 == 0);
}

static void sendmsg_socket_is_not_bound(void)
{
	test (1 == 0);
}

static void sendmsg_ok(void)
{
	test (1 == 0);
}
