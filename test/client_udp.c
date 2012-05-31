#include "../src/kernel/swift.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <time.h>

#define ADDR 0x8082A8C0
#define DADDR 0x8082A8C0

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

    sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        perror("Failed to create socket");
        return -1;
    }

	struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(saddr));

	saddr.sin_addr.s_addr = ADDR;
	saddr.sin_port = gen_port();
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

	to.sin_addr.s_addr = DADDR;
	to.sin_port = 100;
	to.sin_family = AF_INET;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = &to;
    msg.msg_namelen = sizeof(to);

    int ret;

    ret = sendmsg(sock, &msg, sizeof(msg));
    if (ret < 0) {
        perror("Failed to send on socket");
        return -1;
    }

    printf("Sent %d bytes on socket\n", msg.msg_namelen);

    if (close(sock) < 0) {
        perror("Failed to close socket");
        return -1;
    }

    return 0;
}
