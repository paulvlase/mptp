#ifndef _SWIFT_H
#define _SWIFT_H

#define IPPROTO_SWIFT 137

#define sockaddr_swift sockaddr_in
#define MIN_SWIFT_PORT 1
#define MAX_SWIFT_PORT 256

#ifdef __KERNEL__
struct swifthdr {
	uint8_t src;
	uint8_t dst;
	__be16 len;
};
#endif

#endif
