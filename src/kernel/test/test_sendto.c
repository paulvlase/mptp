/*
 * Test sendto "syscall".
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

static void sendto_dummy(void);
static void sendto_invalid_descriptor(void);
static void sendto_descriptor_is_not_socket(void);
static void sendto_socket_is_not_bound(void);
static void sendto_ok(void);

// Additional function
static void fill_sockaddr_sw(struct sockaddr_sw *local_addr, struct sockaddr_sw *remote_addr, char * local_address, char * hash, char * dest_address);

void sendto_test_suite(void)
{
	start_suite();
	sendto_dummy();

	sendto_invalid_descriptor();
	sendto_descriptor_is_not_socket();
	sendto_socket_is_not_bound();
	sendto_ok();
}

static void sendto_dummy(void)
{
	test(1 == 1);
}

static void sendto_invalid_descriptor() 
{
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_sent;
	char buffer[BUFSIZ];

	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");
	bytes_sent = sendto(-1, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	test(bytes_sent < 0 && errno == EBADF);
}

static void sendto_descriptor_is_not_socket(void)
{
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_sent;
	char buffer[BUFSIZ];

	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");
	bytes_sent = sendto(1, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	test(bytes_sent < 0 && errno == ENOTSOCK);
}

static void sendto_socket_is_not_bound(void)
{
	int sockfd;
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_sent;
	char buffer[BUFSIZ];
	
	sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(sockfd < 0, "socket");	
	
	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");
	bytes_sent = sendto(sockfd, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));

	test( bytes_sent < 0 && errno == EAFNOSUPPORT );
}

static void sendto_ok(void) 
{
	int sockfd;
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	ssize_t bytes_sent;
	char buffer[BUFSIZ];
	int rc;

	fill_sockaddr_sw(&local_addr, &remote_addr, "127.0.0.1", "myHash", "127.0.0.1");

	sockfd = socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(sockfd < 0, "socket");

	rc = bind(sockfd, (struct sockaddr *) &local_addr, sizeof(local_addr));
	DIE(rc < 0, "bind");

	bytes_sent = sendto(sockfd, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
	
	perror("sendto");
	test( bytes_sent >= 0 );

}

static void fill_sockaddr_sw(struct sockaddr_sw *local_addr, struct sockaddr_sw *remote_addr, char * local_address, char * hash, char * dest_address) 
{
	inet_pton(PF_INET, local_address, &(local_addr->sin_addr));
	memcpy(&local_addr->sw_hash, hash, sizeof(struct sw_hash));

	inet_pton(PF_INET, dest_address, &(remote_addr->sin_addr));
	memcpy(&remote_addr->sw_hash, hash, sizeof(struct sw_hash));
}
