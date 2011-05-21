/*
 * swift implementation of syscall API>
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
#include <unistd.h>
#include <errno.h>

#include "swift_types.h"
#include "swift_raw.h"

/* socket management structure */
struct sock_list {
	int s;
	struct sockaddr_sw addr;
	struct sock_list *next;
	struct sock_list *prev;
};

static struct sock_list sock_list_head = {
	.next = &sock_list_head,
	.prev = &sock_list_head
};

/*
 * Add new socket to list. Called by sw_socket "syscall".
 */

static struct sock_list *list_add_socket(int s)
{
	struct sock_list *ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return NULL;

	ptr->next = &sock_list_head;
	ptr->prev = sock_list_head.prev;
	sock_list_head.prev->next = ptr;
	sock_list_head.prev = ptr;

	return ptr;
}

/*
 * Bind socket to given address. Called by sw_bind "syscall".
 */

static struct sock_list *list_update_socket_address(int s, struct sockaddr_sw *addr)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s) {
			memcpy(&ptr->addr, addr, sizeof(ptr->addr));
			return ptr;
		}

	return NULL;
}

/*
 * Get list element containing socket s. Called by sw_send* "syscalls".
 */

static struct sock_list *list_elem_from_socket(int s)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s) {
			return ptr;
		}

	return NULL;
}

/*
 * Get list element containing address addr. Called by sw_bind "syscall".
 */

static struct sock_list *list_elem_from_address(const struct sockaddr_sw *addr)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (memcmp(&ptr->addr, addr, sizeof(addr)) == 0)
			return ptr;

	return NULL;
}

/*
 * Remove socket from list. Called by sw_close "syscall".
 */

static struct sock_list *list_unlink_socket(int s)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s) {
			ptr->next->prev = ptr->prev;
			ptr->prev->next = ptr->next;
			ptr->next = ptr;
			ptr->prev = ptr;
			return ptr;
		}

	return NULL;
}

/*
 * Create a new socket of type TYPE in domain DOMAIN, using
 * protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
 * Returns a file descriptor for the new socket, or -1 for errors.
 *
 * swift: PROTOCOL is IPPROTO_SWIFT. Ignore TYPE.
 */
int sw_socket (int __domain, int __type, int __protocol)
{
	int s;
	struct sock_list *list;

	s = socket(__domain, SOCK_RAW, IPPROTO_SWIFT);
	if (s < 0)
		goto sock_err;

	list = list_add_socket(s);
	if (list == NULL)
		goto list_add_err;

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
int sw_bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
	struct sock_list *list;

	/* Check whether address is already in use. */
	list = list_elem_from_address(__addr);
	if (list != NULL) {
		errno = EADDRINUSE;
		goto list_elem_err;
	}
	/* Update __fd entry in socket management list. */
	list = list_update_socket_address(__fd, __addr);
	if (list == NULL) {
		errno = EBADF;
		goto list_update_err;
	}

	return 0;

list_update_err:
list_elem_err:
	return -1;
}

/* Put the local address of FD into *ADDR and its length in *LEN.  */
int sw_getsockname (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len)
{
	/* TODO */

	return 0;
}

/*
 * Send N bytes of BUF on socket FD to peer at address ADDR (which is
 * ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_sendto (int __fd, __const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len)
{
	ssize_t bytes_sent;

	/* TODO */

	return bytes_sent;
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
ssize_t sw_recvfrom (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len)
{
	ssize_t bytes_recv;

	/* TODO */

	return bytes_recv;
}

/*
 * Send a message described MESSAGE on socket FD.
 * Returns the number of bytes sent, or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_sendmsg (int __fd, __const struct msghdr *__message,
			int __flags)
{
	ssize_t bytes_sent;

	/* TODO */

	return bytes_sent;
}

/*
 * Receive a message as described by MESSAGE from socket FD.
 * Returns the number of bytes read or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
ssize_t sw_recvmsg (int __fd, struct msghdr *__message, int __flags)
{
	ssize_t bytes_recv;

	/* TODO */

	return bytes_recv;
}

/*
 * Put the current value for socket FD's option OPTNAME at protocol level
 * LEVEL into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the
 * value's actual length.  Returns 0 on success, -1 for errors.
 */
int sw_getsockopt (int __fd, int __level, int __optname,
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

int sw_setsockopt (int __fd, int __level, int __optname,
		       __const void *__optval, socklen_t __optlen)
{
	/* Call classical interface of setsockopt(2). */
	return setsockopt(__fd, __level, __optname, __optval, __optlen);
}

/*
 * Shut down all or part of the connection open on socket FD.
 * HOW determines what to shut down:
 *   SHUT_RD   = No more receptions;
 *   SHUT_WR   = No more transmissions;
 *   SHUT_RDWR = No more receptions or transmissions.
 * Returns 0 on success, -1 for errors.
 */
int sw_shutdown (int __fd, int __how)
{
	/* Call classical interface of shutdown(2). */
	return shutdown(__fd, __how);
}