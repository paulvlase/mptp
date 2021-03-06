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
	int i;

	if (argc != 3) {
		fprintf(stderr, "USAGE: %s listening_port output_file_name\n",
			argv[0]);
		return -1;
	}

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		perror("Failed to create socket");
		return -1;
	}

	struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));

	inet_pton(AF_INET, ADDR, &saddr.sin_addr.s_addr);
	saddr.sin_port = htons(atoi(argv[1]));
	saddr.sin_family = AF_INET;

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		perror("Failed to bind socket");
		close(sock);
		return -1;
	}

	int fd = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0666);
	if (fd < 0) {
		perror("Failed to open file");
		close(sock);
		return -1;
	}
	
	char buf[8192];
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

		//printf("Received %d bytes on socket\n", ret);
		//printf("buf=%s\n", buf);

		if (ret < 8192)
			break;
	}

	if (close(sock) < 0) {
		perror("Failed to close socket");
		return -1;
	}

	close(fd);

	return 0;
}
