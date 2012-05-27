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

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_SWIFT);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

    int size = sizeof(struct sockaddr_swift) + sizeof(struct swift_dest);
    struct sockaddr_swift *saddr = malloc(size);
    memset(saddr, 0, size);

    saddr->count = 1;
    saddr->dests[0].addr = 0x0100007F;
    saddr->dests[0].port = atoi(argv[1]);

    if (bind(sock, (struct sockaddr *) saddr, size) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[NUM_BUF][10240];
    struct iovec iov[NUM_BUF];
    struct msghdr msg;
	size += (NUM_BUF - 1) * sizeof(struct swift_dest);
    struct sockaddr_swift *from = malloc(size);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(from, 0, size);

	for (i = 0; i < NUM_BUF; i++) {
		iov[i].iov_base = buf[i];
		iov[i].iov_len = sizeof(buf[i]);
	}

    msg.msg_iov = iov;
    msg.msg_iovlen = 10;
    msg.msg_name = from;
    msg.msg_namelen = size;

    int ret, fromlen;

	sleep(20);

    ret = recvmsg(sock, &msg, 0);
    if (ret < 0) {
        perror("Failed to recv on socket");
        return -1;
    }

    printf("Received %d bytes on socket\n", ret);
	for (i = 0; i < from->count; i++) {
		printf("buf=%s from %s:%d\n", buf[i], inet_ntoa(from->dests[i].addr), from->dests[i].port);
	}

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    free(saddr);
    free(from);

    return 0;
}
