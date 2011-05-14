/*
 * swift interface for raw sockets
 *
 * Simulates the classic socket syscalls (socket, bind, send, recv).
 * Implementation uses raw sockets (AF_INET, SOCK_RAW).
 *
 * Subsequently, implementation is to be ported into kernel space and
 * the interface is going to be offered by the Linux syscall API.
 *
 * 2010, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
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
 * swift address
 *   - IP address (Network Layer)
 *   - file hash (or hash for part of a file)
 *       - a seeder (sender) publishes that hash
 *       - a leecher (receiver) requests that hash
 *       - stands as port number both for sender and receiver
 */

#define SWIFT_HASH_SIZE		8

struct sw_hash {
	unsigned char h_array[SWIFT_HASH_SIZE];
};

struct sockaddr_sw {
	__SOCKADDR_COMMON(sin_);
	struct in_addr sin_addr;
	struct sw_hash sw_hash;

	/* Pad to size of `struct sockaddr'.  */
	unsigned char sw_zero[sizeof(struct sockaddr) -
		__SOCKADDR_COMMON_SIZE -
		sizeof(sw_hash) -
		sizeof(struct in_addr)];
};

#ifdef __cplusplus
}
#endif

#endif /* SWIFT_RAW_ */
