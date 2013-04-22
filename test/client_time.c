#include "../src/kernel/mptp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#define ADDR "192.168..56.101"
#define DADDR "192.168.56.101"

int gen_port()
{
	int ret;
	srand(time(NULL));
	ret = (rand() % 255) + 1;
	if (ret == 100 || ret == 101)
		ret *= 2;
	printf("Generated source port %d\n", ret);
	return ret;
}

int main(int argc, const char *argv[])
{
    int sock;

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_MPTP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

    int size = sizeof(struct sockaddr_mptp) + sizeof(struct mptp_dest);
    struct sockaddr_mptp *saddr = malloc(size);
    memset(saddr, 0, size);

    saddr->count = 1;
    inet_aton(ADDR, &(saddr->dests[0].addr));
    saddr->dests[0].port = htons(gen_port());

    if (bind(sock, (struct sockaddr *) saddr, size) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[4096];
	sprintf(buf, "Buffer");

#define N 1
    struct iovec iov[N];
    struct msghdr msg;
    int size2 = sizeof(struct sockaddr_mptp) + N * sizeof(struct mptp_dest);
    struct sockaddr_mptp *to = malloc(size2);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(to, 0, size2);

	int i;
	for (i = 0; i < N; i++) {
		iov[i].iov_base = buf;
		iov[i].iov_len = sizeof(buf);
	}

    to->count = N;
	for (i = 0; i < N; i++) {
    		inet_aton(DADDR, &(to->dests[i].addr));
		to->dests[i].port = htons(100);
	}

    msg.msg_iov = iov;
    msg.msg_iovlen = N;
    msg.msg_name = to;
    msg.msg_namelen = size2;

    int ret;

	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);
	for (i = 0; i < 10000 / N; i++) {
		ret = sendmsg(sock, &msg, sizeof(msg));
		if (ret < 0) {
			perror("Failed to send on socket");
			return -1;
		}
	}
	gettimeofday(&tv2, NULL);

	printf("diff=%ld\n", (tv2.tv_sec - tv1.tv_sec) * 1000 + (tv2.tv_usec - tv1.tv_usec) / 1000);

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    free(saddr);
    free(to);
    return 0;
}
