/*
 * Test sw_bind "syscall".
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "swift_raw.h"
#include "swift_types.h"

#include "debug.h"
#include "util.h"

#include "test_sw.h"
#include "test.h"

static void bind_dummy(void);
static void bind_invalid_descriptor(void);
static void bind_descriptor_not_a_socket(void);
static void bind_invalid_ip_address(void);
static void bind_ok(void);
static void bind_address_in_use(void);
static void bind_socket_already_bound(void);

void bind_test_suite(void)
{
	start_suite();
	bind_dummy();
	bind_invalid_descriptor();
	bind_descriptor_not_a_socket();
	bind_invalid_ip_address();
	bind_ok();
	bind_address_in_use();
	bind_socket_already_bound();
}

static void bind_dummy(void)
{
	test(1 == 1);
}

static void bind_invalid_descriptor(void)
{
	struct sockaddr_sw addr;
	int rc;

	rc = sw_bind(-2, (struct sockaddr *) &addr, sizeof(addr));

	test(rc < 0 && errno == EBADF);
}

static void bind_descriptor_not_a_socket(void)
{
	struct sockaddr_sw addr;
	int fd = dup(STDOUT_FILENO);
	int rc;

	rc = sw_bind(fd, (struct sockaddr *) &addr, sizeof(addr));

	/*
	 * We are unable to properly handle checking whether the file
	 * descriptor is a socket in the raw socket based implementation.
	 * To be updated when porting to the kernel.
	 */
	test(rc < 0 && errno == ENOTSOCK);
}

static void bind_invalid_ip_address(void)
{
	struct sockaddr_sw addr;
	int sockfd;
	int rc;

	sockfd = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "254.254.254.254", &addr.sin_addr.s_addr);
	rc = sw_bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));

	/*
	 * We are unable to properly handle address validation in the raw
	 * socket based implementation.
	 * To be updated when porting to the kernel.
	 */
	test(rc < 0 && errno == EADDRNOTAVAIL);

	sw_close(sockfd);
}

static void bind_ok(void)
{
	struct sockaddr_sw addr;
	int sockfd;
	int rc;

	sockfd = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	rc = sw_bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));

	test(rc == 0);

	sw_close(sockfd);
}

static void bind_address_in_use(void)
{
	struct sockaddr_sw addr1, addr2;
	int sockfd1, sockfd2;
	int rc;

	sockfd1 = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	memset(&addr1, 0, sizeof(addr1));
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = INADDR_ANY;
	rc = sw_bind(sockfd1, (struct sockaddr *) &addr1, sizeof(addr1));
	dprintf("after first sw_bind rc = %d\n", rc);

	sockfd2 = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_addr.s_addr = INADDR_ANY;
	rc = sw_bind(sockfd2, (struct sockaddr *) &addr2, sizeof(addr2));
	dprintf("after second sw_bind rc = %d\n", rc);

	test(rc < 0 && errno == EADDRINUSE);

	sw_close(sockfd1);
	sw_close(sockfd2);
}

static void bind_socket_already_bound(void)
{
	struct sockaddr_sw addr1, addr2;
	int sockfd;
	int rc;

	sockfd = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	memset(&addr1, 0, sizeof(addr1));
	addr1.sin_family = AF_INET;
	addr1.sin_addr.s_addr = INADDR_ANY;
	rc = sw_bind(sockfd, (struct sockaddr *) &addr1, sizeof(addr1));

	memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_addr.s_addr = INADDR_ANY;
	addr2.sw_hash.h_array[0] = 0xFF;	/* chage hash ("port") */
	rc = sw_bind(sockfd, (struct sockaddr *) &addr2, sizeof(addr2));

	test(rc < 0 && errno == EINVAL);

	sw_close(sockfd);
}
