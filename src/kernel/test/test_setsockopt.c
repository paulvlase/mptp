/*
 * Test sw_setsockopt "syscall".
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

void setsockopt_dummy(void)
{
	test(1 == 1);
}
