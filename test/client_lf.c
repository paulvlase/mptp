#include "../src/kernel/mptp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <fcntl.h>

#define ADDR "192.168.56.101"
#define DADDR "192.168.56.101"

int main(int argc, const char *argv[])
{
	int sock;

	if (argc != 2) {
		fprintf(stderr, "USAGE: %s input_file_name\n",
			argv[0]);
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
	inet_aton(ADDR, &(saddr->dests[0].addr));
	saddr->dests[0].port = htons(50);

	if (bind(sock, (struct sockaddr *)saddr, size) < 0) {
		perror("Failed to bind socket");
		close(sock);
		return -1;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		perror("Failed to open file");
		close(sock);
		return -1;
	}

	char buf[8192];
	struct iovec iov[2];
	struct msghdr msg;
	int size2 = sizeof(struct sockaddr_mptp) + 2 * sizeof(struct mptp_dest);
	struct sockaddr_mptp *to = malloc(size2);

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	memset(to, 0, size2);

	iov[0].iov_base = buf;
	iov[1].iov_base = buf;

	to->count = 2;
	inet_aton(DADDR, &(to->dests[0].addr));
	to->dests[0].port = htons(100);
	inet_aton(DADDR, &(to->dests[1].addr));
	to->dests[1].port = htons(101);

	msg.msg_iov = iov;
	msg.msg_iovlen = 2;
	msg.msg_name = to;
	msg.msg_namelen = size2;

	while (1) {
		int ret;

		ret = read(fd, buf, 8192, 0);
		if (ret == 0)
			break;
		if (ret < 0) {
			perror("Failed to read from file");
			return -1;
		}
		iov[0].iov_len = ret;
		iov[1].iov_len = ret;

		ret = sendmsg(sock, &msg, sizeof(msg));
		if (ret < 0) {
			perror("Failed to send on socket");
			return -1;
		}

		//printf("Sent %d bytes on socket\n", msg.msg_namelen);
	}

	if (close(sock) < 0) {
		perror("Failed to close socket");
		close(fd);
		return -1;
	}

	close(fd);

	free(saddr);
	free(to);
	return 0;
}
