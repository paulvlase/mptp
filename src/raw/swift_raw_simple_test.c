/*
 * Simple test for raw socket based implementation of swift socket API.
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include "swift_types.h"
#include "swift_raw.h"
#include "debug.h"
#include "util.h"

static void usage(const char *argv0)
{
	fprintf(stderr, "Usage: %s local_address swift_hash [remote_address]\n", argv0);
}

/*
 * Create a socket, bind it and send data.
 */
int main(int argc, char *argv[])
{
	int sockfd;
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	char buffer[BUFSIZ];
	ssize_t bytes_sent;
	int rc;

	if (argc != 3 && argc != 4) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	sockfd = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(sockfd < 0, "sw_socket");

	memset(&local_addr, 0, sizeof(local_addr));
	inet_pton(AF_INET, argv[1], &local_addr.sin_addr.s_addr);
	memcpy(&local_addr.sw_hash, argv[2], sizeof(struct sw_hash));
	rc = sw_bind(sockfd, (struct sockaddr *) &local_addr, sizeof(local_addr));
	DIE(rc < 0, "sw_bind");

	if (argc > 3) {
		inet_pton(AF_INET, argv[3], &remote_addr.sin_addr.s_addr);
		memcpy(&remote_addr.sw_hash, argv[2], sizeof(struct sw_hash));
		bytes_sent = sw_sendto(sockfd, buffer, BUFSIZ, 0, (struct sockaddr *) &remote_addr, sizeof(remote_addr));
		DIE(bytes_sent < 0, "sw_sendto");
	}

	return 0;
}
