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

// Additional function
static void fill_sockaddr_sw(struct sockaddr_sw *local_addr, struct sockaddr_sw *remote_addr, char * local_address, char * hash, char * dest_address);

void recvfrom_test_suite(void)
{
	start_suite();
	recvfrom_dummy();
	recvfrom_invalid_descriptor();
	recvfrom_descriptor_is_not_a_socket();
	recvfrom_socket_is_not_bound();
	recvfrom_after_sendto_ok();
	recvfrom_after_sendmsg_ok();
}

static void recvfrom_dummy(void)
{
	test(1 == 1);
}

static void recvfrom_invalid_descriptor(void) 
{
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_recv;
	char buffer[BUFSIZ];

	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");
	bytes_recv = sw_recvfrom(-1, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	test(bytes_recv < 0 && errno == EBADF);
}

static void recvfrom_descriptor_is_not_a_socket(void)
{
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_recv;
	char buffer[BUFSIZ];

	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");
	bytes_recv = sw_recvfrom(1, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	test(bytes_recv < 0 && errno == ENOTSOCK);
}

static void recvfrom_socket_is_not_bound(void) 
{
	int sockfd;
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_recv;
	char buffer[BUFSIZ];
						
	sockfd = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(sockfd < 0, "sw_socket");	
								
	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");
	bytes_recv = sw_recvfrom(sockfd, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	test( bytes_recv < 0 && errno == EAFNOSUPPORT );
}

static void recvfrom_after_sendto_ok(void)
{
		test ( 0 == 1 );
}

static void recvfrom_after_sendmsg_ok(void)
{
		test ( 0 == 1 );
}

static void fill_sockaddr_sw(struct sockaddr_sw *local_addr, struct sockaddr_sw *remote_addr, char * local_address, char * hash, char * dest_address) 
{
	local_addr->sin_addr.s_addr = htonl((int)local_address);
	memcpy(&local_addr->sw_hash, hash, sizeof(struct sw_hash));

	remote_addr->sin_addr.s_addr = htonl((int)dest_address);
	memcpy(&remote_addr->sw_hash, hash, sizeof(struct sw_hash));
}
