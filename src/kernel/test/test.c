/*
 * Test swift. Imports functions from test_sw_* files and runs tests.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "debug.h"
#include "util.h"

#include "test_sw.h"

static void (*test_fun_array[])(void) = {
	NULL,
	test_dummy,
	socket_test_suite,
	bind_test_suite,
	getsockname_test_suite,
	getsockopt_test_suite,
	sendto_test_suite,
	recvfrom_test_suite,
	sendmsg_test_suite,
	recvmsg_test_suite,
	close_test_suite,
};

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s [test_no]\n\n", argv0);
	exit(EXIT_FAILURE);
}

/*
 * In case of no arguments call all functions defined in test_fun_array.
 */

int main(int argc, char **argv)
{
	int test_idx;

	/* No arguments: call all test functions. */
	if (argc == 1) {
		int i;
		for (i = 1; i < sizeof(test_fun_array)/sizeof(test_fun_array[0]); i++)
			test_fun_array[i]();
		return 0;
	}

	if (argc != 2)
		usage(argv[0]);

	test_idx = atoi(argv[1]);

	if (test_idx < 1 || test_idx >= sizeof(test_fun_array)/sizeof(test_fun_array[0])) {
		fprintf(stderr, "Error: test index %d is out of bounds\n", test_idx);
		exit(EXIT_FAILURE);
	}

	test_fun_array[test_idx]();

	return 0;
}
