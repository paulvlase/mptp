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
static void close_ok_descriptor_is_not_bound(void);
static void close_ok_descriptor_is_bound(void);

void close_test_suite(void)
{
	start_suite();
	close_dummy();
	close_invalid_descriptor();
	close_descriptor_is_not_a_socket();
	close_ok_descriptor_is_not_bound();
	close_ok_descriptor_is_bound();
}

static void close_dummy(void)
{
	test(1 == 1);
}

/* Pass invalid file descriptor to sw_close. */
static void close_invalid_descriptor(void)
{
	int rc;

	rc = sw_close(-1);

	test(rc < 0 && errno == EBADF);
}

/* Pass a duplicate of standard output to sw_close. */
static void close_descriptor_is_not_a_socket(void)
{
	int fd;
	int rc;

	fd = dup(STDOUT_FILENO);
	DIE(fd < 0, "dup");

	rc = sw_close(fd);

	test(rc < 0 && errno == EBADF);

	close(fd);
}

/* Pass a non-bound socket. */
static void close_ok_descriptor_is_not_bound(void)
{
	int s;
	int rc;

	s = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(s < 0, "sw_socket");

	rc = sw_close(s);

	test(rc == 0);
}

/* Pass a bound socket. */
static void close_ok_descriptor_is_bound(void)
{
	int s;
	int rc;
	struct sockaddr_sw addr;

	s = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(s < 0, "sw_socket");

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	rc = sw_bind(s, (struct sockaddr *) &addr, sizeof(addr));
	DIE(rc < 0, "sw_bind");

	rc = sw_close(s);

	test(rc == 0);
}
