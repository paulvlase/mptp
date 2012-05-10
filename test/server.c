#include "../src/kernel/swift.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>

int main(int argc, const char *argv[])
{
    int sock;

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
    saddr->dests[0].port = 100;

    if (bind(sock, (struct sockaddr *) saddr, size) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[256];
    struct iovec iov[1];
    struct msghdr msg;
    struct sockaddr_swift *from = malloc(size);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(from, 0, size);

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = from;
    msg.msg_namelen = size;

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

    free(saddr);
    free(from);

    return 0;
}
