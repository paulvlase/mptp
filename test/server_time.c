#include "../src/kernel/mptp.h"

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

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_MPTP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

    int size = sizeof(struct sockaddr_mptp) + sizeof(struct mptp_dest);
    struct sockaddr_mptp *saddr = malloc(size);
    memset(saddr, 0, size);

    saddr->count = 1;
    saddr->dests[0].addr = ADDR;
    saddr->dests[0].port = atoi(argv[1]);

    if (bind(sock, (struct sockaddr *) saddr, size) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

#define N 16
    char buf[N][4096];
    struct iovec iov[N];
    struct msghdr msg;
	size += (N - 1) * sizeof(struct mptp_dest);
    struct sockaddr_mptp *from = malloc(size);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(from, 0, size);

	for (i = 0; i < N; i++) {
		iov[i].iov_base = buf[i];
		iov[i].iov_len = sizeof(buf[i]);
	}

    msg.msg_iov = iov;
    msg.msg_iovlen = N;
    msg.msg_name = from;
    msg.msg_namelen = size;

    int ret, fromlen;

#define COUNT (10000/(N))

	for (i = 0; i < COUNT; i++) {
		ret = recvmsg(sock, &msg, 0);
		if (ret < 0) {
			perror("Failed to recv on socket");
			return -1;
		}
		if (i % (COUNT/50) == 0)
			printf("%d\n", i);
	}

    printf("Received %d bytes on socket\n", ret);

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    free(saddr);
    free(from);

    return 0;
}
