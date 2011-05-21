/*
 * swift interface for raw sockets
 *
 * Simulates the classic socket syscalls (socket, bind, send, recv).
 * Implementation uses raw sockets (AF_INET, SOCK_RAW).
 *
 * Subsequently, implementation is to be ported into kernel space and
 * the interface is going to be offered by the Linux syscall API.
 *
 * Heavily inspired from GLIBC's <sys/socket.h>
 * (/usr/include/sys/socket.h).
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#ifndef SWIFT_RAW_
#define SWIFT_RAW_	1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Create a new socket of type TYPE in domain DOMAIN, using
 * protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
 * Returns a file descriptor for the new socket, or -1 for errors.
 *
 * swift: protocol is IPPROTO_SWIFT.
 */
extern int sw_socket (int __domain, int __type, int __protocol) __THROW;

/*
 * Give the socket FD the local address ADDR (which is LEN bytes long).
 *
 * swift: ADDR is of type struct sockaddr_sw.
 */
extern int sw_bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
     __THROW;

/* Put the local address of FD into *ADDR and its length in *LEN.  */
extern int sw_getsockname (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len) __THROW;

/*
 * Send N bytes of BUF on socket FD to peer at address ADDR (which is
 * ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
extern ssize_t sw_sendto (int __fd, __const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len);

/*
 * Read N bytes into BUF through socket FD.
 * If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
 * the sender, and store the actual size of the address in *ADDR_LEN.
 * Returns the number of bytes read or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
extern ssize_t sw_recvfrom (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len);

/*
 * Send a message described MESSAGE on socket FD.
 * Returns the number of bytes sent, or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
extern ssize_t sw_sendmsg (int __fd, __const struct msghdr *__message,
			int __flags);

/*
 * Receive a message as described by MESSAGE from socket FD.
 * Returns the number of bytes read or -1 for errors.
 *
 * This function is a cancellation point and therefore not marked with
 * __THROW.
 */
extern ssize_t sw_recvmsg (int __fd, struct msghdr *__message, int __flags);

/*
 * Put the current value for socket FD's option OPTNAME at protocol level
 * LEVEL into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the
 * value's actual length.  Returns 0 on success, -1 for errors.
 */
extern int sw_getsockopt (int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen) __THROW;

/*
 * Set socket FD's option OPTNAME at protocol level LEVEL
 * to *OPTVAL (which is OPTLEN bytes long).
 * Returns 0 on success, -1 for errors.
 */

extern int sw_setsockopt (int __fd, int __level, int __optname,
		       __const void *__optval, socklen_t __optlen) __THROW;

/*
 * Close file descriptor for socket FD.
 * Returns 0 on success, -1 for errors.
 */
extern int sw_close (int __fd);

#ifdef __cplusplus
}
#endif

#endif /* SWIFT_RAW_ */
