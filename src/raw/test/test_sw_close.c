/*
 * Test sw_close "syscall".
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

