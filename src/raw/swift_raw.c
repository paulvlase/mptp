/*
 * swift implementation of syscall API
 *
 * Simulates the classic socket syscalls (socket, bind, send, recv).
 * Implementation uses raw sockets (AF_INET, SOCK_RAW).
 *
 * Subsequently, implementation is to be ported into kernel space and
 * the interface is going to be offered by the Linux syscall API.
 *
 * Heavily inspired by GLIBC's <sys/socket.h>
 * (/usr/include/sys/socket.h).
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#include "swift_types.h"
#include "swift_raw.h"
#include "socket_manager.h"
#include "debug.h"
#include "util.h"

/*
 * Create a new socket of type TYPE in domain DOMAIN, using
 * protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
 * Returns a file descriptor for the new socket, or -1 for errors.
 *
 * swift: PROTOCOL is IPPROTO_SWIFT. Ignore TYPE.
 */
int sw_socket(int __domain, int __type, int __protocol)
{
	int s;
	int rc;

	if (__domain != PF_INET || __type != SOCK_DGRAM || __protocol != IPPROTO_SWIFT) {
		errno = EINVAL;
		goto sock_err;
	}

	s = socket(PF_INET, SOCK_RAW, IPPROTO_SWIFT);
	if (s < 0) {
		goto sock_err;
	}

	rc = sm_add(s);
	if (rc < 0) {
		errno = ENOMEM;
		goto list_add_err;
	}

	/* Socket is not bound. */
	sm_mark_unbound(s);

	return s;

list_add_err:
	close(s);
sock_err:
	return -1;
}

/*
 * Give the socket FD the local address ADDR (which is LEN bytes long).
 *
 * swift: ADDR is of type struct sockaddr_sw.
 */
int sw_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
	int rc;

	rc = sm_is_bound(__fd);
	if (rc == 1) {
		errno = EINVAL;
		goto socket_bound_err;
	}

	/* Check whether address is already in use. */
	rc = sm_address_exists(__addr);
	if (rc == 1) {
		errno = EADDRINUSE;
		goto address_err;
	}

	/* Update __fd entry in socket management list. */
	rc = sm_update_address(__fd, __addr);
	if (rc < 0) {
		errno = EBADF;
		goto update_err;
	}

	sm_mark_bound(__fd);

	return 0;

update_err:
address_err:
socket_bound_err:
	return -1;
}

/* Put the local address of FD into *ADDR and its length in *LEN.  */
int sw_getsockname(int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len)
{
	struct sockaddr *addr;

	/* Find socket in management structure. */
	addr = sm_get_address(__fd);
	if (addr == NULL) {
		errno = EINVAL;
		goto address_err;
	}

	memcpy(__addr, &addr, sizeof(addr));
	*__len = sizeof(addr);

	return 0;

address_err:
	return -1;
}

/*
 * Send N bytes of BUF on socket FD to peer at address ADDR (which is
 * ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_sendto(int __fd, __const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len)
{
	ssize_t bytes_sent;
	struct iovec __iov[1];
	struct msghdr __msgh;
	struct sockaddr_sw *__sw_addr = (struct sockaddr_sw *) __addr;
	int rc;

	rc = sm_is_bound(__fd);
	if (rc < 0) {
		errno = EAFNOSUPPORT;
		goto sock_err;
	}

	{
		char str[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &(__sw_addr->sin_addr), str, INET_ADDRSTRLEN);	
		printf("=== ADDR: %s ===\n", str);
	}

	/* Specify the components of the message in an "iovec".   */
	__iov[0].iov_base = (void *) __buf;
	__iov[0].iov_len = __n;
	
	/* The message header contains parameters for sendmsg.    */
	__msgh.msg_name = (caddr_t) __addr;
	__msgh.msg_namelen = sizeof(__addr);
	__msgh.msg_iov = __iov;
	__msgh.msg_iovlen = 1;
	__msgh.msg_control = NULL;            /* irrelevant to AF_INET */
	__msgh.msg_controllen = 0;            /* irrelevant to AF_INET */

	return sendmsg(__fd, &__msgh, 0);

sock_err:
	return -1;
}

/*
 * Read N bytes into BUF through socket FD.
 * If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
 * the sender, and store the actual size of the address in *ADDR_LEN.
 * Returns the number of bytes read or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_recvfrom(int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len)
{
	ssize_t bytes_recv;
	struct iovec __iov[1];
	struct msghdr __msgh;
	struct sockaddr_sw *__sw_addr = (struct sockaddr_sw *) __addr;
	int rc;

	rc = sm_is_bound(__fd);
	if (rc < 0) {
		errno = EAFNOSUPPORT;
		goto sock_err;
	}

	/* TODO */

	return recvmsg(__fd, &__msgh, 0);
	
sock_err:
	return -1;
}

/*
 * Send a message described MESSAGE on socket FD.
 * Returns the number of bytes sent, or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_sendmsg(int __fd, __const struct msghdr *__message,
			int __flags)
{
	ssize_t bytes_sent;

	/* TODO */
	
	return sendmsg(__fd, __message, __flags);
}

/*
 * Receive a message as described by MESSAGE from socket FD.
 * Returns the number of bytes read or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_recvmsg(int __fd, struct msghdr *__message, int __flags)
{
	ssize_t bytes_recv;

	/* TODO */

	return recvmsg(__fd, __message, __flags);
}

/*
 * Put the current value for socket FD's option OPTNAME at protocol level
 * LEVEL into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the
 * value's actual length.  Returns 0 on success, -1 for errors.
 */
int sw_getsockopt(int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen)
{
	/* Call classical interface of getsockopt(2). */
	return getsockopt(__fd, __level, __optname, __optval, __optlen);
}

/*
 * Set socket FD's option OPTNAME at protocol level LEVEL
 * to *OPTVAL (which is OPTLEN bytes long).
 * Returns 0 on success, -1 for errors.
 */
int sw_setsockopt(int __fd, int __level, int __optname,
		       __const void *__optval, socklen_t __optlen)
{
	/* Call classical interface of setsockopt(2). */
	return setsockopt(__fd, __level, __optname, __optval, __optlen);
}

/*
 * Close file descriptor for socket FD.
 * Returns 0 on success, -1 for errors.
 */
int sw_close(int __fd)
{
	int rc;

	/* Remove socket from socket management structure. */
	rc = sm_del(__fd);
	if (rc < 0) {
		errno = EBADF;
		goto del_err;
	}

	/* Call classical interface of close(2). */
	return close(__fd);

del_err:
	return -1;
}
