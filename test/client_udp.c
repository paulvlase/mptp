#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, const char *argv[])
{
    int sock;
	int i;

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

	struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));

	inet_pton(AF_INET, "192.168.130.128", &saddr.sin_addr.s_addr);
	saddr.sin_port = 0;
	saddr.sin_family = AF_INET;

    if (bind(sock, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[4096];
	sprintf(buf, "Buffer");
    struct iovec iov[1];
    struct msghdr msg;
    struct sockaddr_in to;

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(&to, 0, sizeof(to));

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

	inet_pton(AF_INET, "192.168.130.129", &to.sin_addr.s_addr);
	to.sin_port = htons(100);
	to.sin_family = AF_INET;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &to;
    msg.msg_namelen = sizeof(to);

    int ret;

	struct timeval tv1, tv2;
	gettimeofday(&tv1, NULL);
	for (i = 0; i < 10000; i++) {
		ret = sendmsg(sock, &msg, 0);
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

    return 0;
}
