/*
 * Simple test for raw socket based implementation of swift socket API.
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "swift_types.h"
#include "swift_raw.h"
#include "util.h"

/*
 * Create a socket, bind it and send data.
 */
int main(void)
{
	int sockfd;
	struct sockaddr_sw local_addr;
	struct sockaddr_sw remote_addr;
	char buffer[BUFSIZ];
	ssize_t bytes_sent;
	int rc;

	sockfd = sw_socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
	DIE(sockfd < 0, "sw_socket");

	/* TODO: init_addr */

	rc = sw_bind(sockfd, (struct sockaddr *) &local_addr, sizeof(local_addr));
	DIE(rc < 0, "sw_bind");

	/* TODO: init remote_addr */
	bytes_sent = sw_sendto(sockfd, buffer, BUFSIZ, 0,
			(struct sockaddr *) &remote_addr, sizeof(remote_addr));
	DIE(bytes_sent < 0, "sw_sendto");

	return 0;
}
