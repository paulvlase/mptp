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

	sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		perror("Failed to create socket");
		return -1;
	}

	struct sockaddr_in saddr;
	memset(&saddr, 0, sizeof(saddr));

	inet_pton(AF_INET, ADDR, &saddr.sin_addr.s_addr);
	saddr.sin_port = 0;
	saddr.sin_family = AF_INET;

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
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
	struct iovec iov1[1], iov2[1];
	struct msghdr msg1, msg2;
	struct sockaddr_in to1, to2;

	memset(&msg1, 0, sizeof(msg1));
	memset(&iov1, 0, sizeof(iov1));
	memset(&to1, 0, sizeof(to1));

	memset(&msg2, 0, sizeof(msg2));
	memset(&iov2, 0, sizeof(iov2));
	memset(&to2, 0, sizeof(to2));

	iov1[0].iov_base = buf;
	iov1[0].iov_len = sizeof(buf);
	iov2[0].iov_base = buf;
	iov2[0].iov_len = sizeof(buf);
	
	inet_pton(AF_INET, DADDR, &to1.sin_addr.s_addr);
	to1.sin_port = htons(100);
	to1.sin_family = AF_INET;

	inet_pton(AF_INET, DADDR, &to2.sin_addr.s_addr);
	to2.sin_port = htons(101);
	to2.sin_family = AF_INET;

	msg1.msg_iov = iov1;
	msg1.msg_iovlen = 1;
	msg1.msg_name = &to1;
	msg1.msg_namelen = sizeof(to1);

	msg2.msg_iov = iov2;
	msg2.msg_iovlen = 1;
	msg2.msg_name = &to2;
	msg2.msg_namelen = sizeof(to2);


	while (1) {
		int ret;

		ret = read(fd, buf, 8192, 0);
		if (ret == 0)
			break;
		if (ret < 0) {
			perror("Failed to read from file");
			return -1;
		}
		iov1[0].iov_len = ret;
		iov2[0].iov_len = ret;

		ret = sendmsg(sock, &msg1, 0);
		if (ret < 0) {
			perror("Failed to send on socket");
			return -1;
		}

		//printf("Sent %d bytes on socket [1]\n", msg[0].msg_namelen);

		ret = sendmsg(sock, &msg2, 0);
		if (ret < 0) {
			perror("Failed to send on socket");
			return -1;
		}

		//printf("Sent %d bytes on socket [2]\n", msg[1].msg_namelen);
	}

	if (close(sock) < 0) {
		perror("Failed to close socket");
		return -1;
	}

	close(fd);

	return 0;
}
