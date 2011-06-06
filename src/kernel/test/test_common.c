/*
 * Test suite functions.
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>

#include "util.h"
#include "test.h"

/* Run test function f in another process. */
void run_as_child_process(test_fn f)
{
	pid_t pid;
	int status;
	int rc;

	pid = fork();
	switch (pid) {
	case -1:	/* error */
		ERR("fork");
		exit(EXIT_FAILURE);
	
	case 0:		/* child process */
		/* Run test function. */
		f();
		exit(EXIT_SUCCESS);
		break;
	
	default:	/* parent process */
		break;
	}

	/* Wait for child process. */
	rc = waitpid(pid, &status, 0);
	DIE(rc < 0, "waitpid");
}
