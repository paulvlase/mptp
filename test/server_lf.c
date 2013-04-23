#include "../src/kernel/mptp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <fcntl.h>

#define ADDR "192.168.56.101"

int main(int argc, const char *argv[])
{
	int sock;

	if (argc != 3) {
		fprintf(stderr, "USAGE: %s listening_port output_file_name\n",
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
	saddr->dests[0].port = htons(atoi(argv[1]));

	if (bind(sock, (struct sockaddr *)saddr, size) < 0) {
		perror("Failed to bind socket");
		close(sock);
		return -1;
	}

	int fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC);
	if (fd < 0) {
		perror("Failed to open file");
		close(sock);
		return -1;
	}

	char buf[8192];
	struct iovec iov[1];
	struct msghdr msg;
	struct sockaddr_mptp *from = malloc(size);

	memset(&msg, 0, sizeof(msg));
	memset(&iov, 0, sizeof(iov));
	memset(from, 0, size);

	iov[0].iov_base = buf;
	iov[0].iov_len = sizeof(buf);

	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_name = from;
	msg.msg_namelen = size;

	while (1) {
		int ret, fromlen;

		ret = recvmsg(sock, &msg, 0);
		if (ret < 0) {
			perror("Failed to recv on socket");
			close(fd);
			return -1;
		}

		ret = write(fd, buf, ret, 0);
		if (ret < 0) {
			perror("Failed to write in file");
			close(fd);
			return -1;
		}

		printf("Received %d bytes on socket\n", ret);
		printf("buf=%s\n", buf);

		if (ret < 8192)
			break;
	}

	if (close(sock) < 0) {
		perror("Failed to close socket");
		close(fd);
		return -1;
	}

	close(fd);

	free(saddr);
	free(from);

	return 0;
}
