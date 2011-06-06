/*
 * Test socket "syscall".
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
	socket_invalid_domain();
	socket_invalid_type();
	socket_invalid_protocol();
	run_as_child_process(socket_insufficient_file_descriptors);
	socket_ok();
}

/* Dummy function for testing purposes only. */
static void socket_dummy(void)
{
	test(1 == 1);
}

/* Use invalid domain when calling socket. */
static void socket_invalid_domain(void)
{
	int rc;

	rc = socket(PF_UNIX, SOCK_DGRAM, IPPROTO_SWIFT);

	test(rc < 0 && errno == EINVAL);
}

/* Use invalid type when calling socket. */
static void socket_invalid_type(void)
{
	int rc;

	rc = socket(PF_INET, SOCK_STREAM, IPPROTO_SWIFT);

	test(rc < 0 && errno == EINVAL);
}

/* Use invalid protocol when calling socket. */
static void socket_invalid_protocol(void)
{
	int rc;

	rc = socket(PF_INET, SOCK_DGRAM, -1);

	test(rc < 0 && errno == EINVAL);
}

/*
 * Use dup to fill the number of file descriptors for current process.
 * Calling socket must result in error.
 *
 * File descriptors are not closed. Test processes must be restarted.
 */
static void socket_insufficient_file_descriptors(void)
{
	int fd;
	int rc;

	while (1) {
		/* Duplicate standard output. */
		fd = dup(STDOUT_FILENO);
		if (fd < 0)
			break;
	}

	rc = socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);

	dprintf("errno = %d\n", errno);
	test(rc < 0 && errno == EMFILE);
}

/* Valid call of socket. */
static void socket_ok(void)
{
	int rc;

	rc = socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	dprintf("rc = %d, errno = %d\n", rc, errno);

	test(rc > 0);
}
