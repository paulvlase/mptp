/*
 * swift data structures
 *
 * swift struct sockaddr is dubbed struct sockaddr_sw.
 * swhdr is swift packet header (as delivered on the network).
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#ifndef SWIFT_TYPES_
#define SWIFT_TYPES_	1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 143 is a free IP protocol number (as shown in /etc/protocols
 * and <netinet/in.h>).
 */

#define IPPROTO_SWIFT		143

/*
 * swift address
 *   - IP address (Network Layer)
 *   - file hash (or hash for part of a file)
 *       - a seeder (sender) publishes that hash
 *       - a leecher (receiver) requests that hash
 *       - stands as port number both for sender and receiver
 */

#define SWIFT_HASH_SIZE		8
struct sw_state {
	unsigned int state:4;
	unsigned int info:4;
};

struct sw_hash {
	u_int8_t h_array[SWIFT_HASH_SIZE];
};

struct sockaddr_sw {
	__SOCKADDR_COMMON(sin_);
	struct in_addr sin_addr;
	struct sw_hash sw_hash;

	/* Pad to size of `struct sockaddr'.  */
	unsigned char sw_zero[sizeof(struct sockaddr) -
		__SOCKADDR_COMMON_SIZE -
		sizeof(struct sw_hash) -
		sizeof(struct in_addr)];
};

/*
 * swift header (work in progress)
 */

struct swhdr {
	/* file hash (to be seeded or requested) */
	struct sw_hash base_hash;
	u_int8_t piece_hash;
	struct sw_state sock_state;
};

#ifdef __cplusplus
}
#endif

#endif /* SWIFT_TYPES_ */
