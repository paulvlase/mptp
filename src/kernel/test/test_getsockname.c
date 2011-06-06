/*
 * Test getsockname "syscall".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>

#include "swift_types.h"

#include "debug.h"
#include "util.h"

#include "test_sw.h"
#include "test.h"

static void getsockname_dummy(void);
static void getsockname_invalid_descriptor(void);
static void getsockname_descriptor_not_a_socket(void);
static void getsockname_invalid_len(void);
static void getsockname_ok(void);

void getsockname_test_suite(void)
{
	start_suite();
	getsockname_dummy();
}

static void getsockname_dummy(void)
{
	test(1 == 1);
}

