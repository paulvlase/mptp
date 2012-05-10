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
    saddr->dests[0].port = 50;

    if (bind(sock, (struct sockaddr *) saddr, size) < 0) {
        perror("Failed to bind socket");
        close(sock);
        return -1;
    }

    char buf[] = "Buffer de test";
    struct iovec iov[1];
    struct msghdr msg;
    struct sockaddr_swift *to = malloc(size);

    memset(&msg, 0, sizeof(msg));
    memset(&iov, 0, sizeof(iov));
    memset(to, 0, size);

    iov[0].iov_base = buf;
    iov[0].iov_len = sizeof(buf);

    to->count = 1;
    to->dests[0].addr = 0x0100007F;
    to->dests[0].port = 100;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_name = to;
    msg.msg_namelen = size;

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

    free(saddr);
    free(to);
    return 0;
}
