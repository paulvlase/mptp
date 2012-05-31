#include "../src/kernel/swift.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

#define ADDR 0x8182A8C0
#define NUM_BUF 10

int main(int argc, const char *argv[])
{
    int sock;
	int i;

    if (argc != 2) {
        fprintf(stderr, "USAGE: %s listening_port\n", argv[0]);
        return -1;
    }

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));

	saddr.sin_addr.s_addr = ADDR;
	saddr.sin_port = htons(atoi(argv[1]));
	saddr.sin_family = AF_INET;

    if (bind(sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[4096];
    struct iovec iov[1];
    struct msghdr msg;
    struct sockaddr_in from;

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&from, 0, sizeof(from));

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);

    int ret, fromlen;

    ret = recvmsg(sock, &msg, 0);
    if (ret < 0) {
        perror("Failed to recv on socket");
        return -1;
    }

    printf("Received %d bytes on socket\n", ret);
	printf("buf=%s\n", buf);

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    return 0;
}
