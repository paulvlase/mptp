#ifndef _SWIFT_H
#define _SWIFT_H

#define IPPROTO_SWIFT 137

#define MIN_SWIFT_PORT 1
#define MAX_SWIFT_PORT 256

#ifndef __KERNEL__
#include <inttypes.h>
#endif

struct swift_dest {
    uint32_t addr;
    uint8_t port;
};

struct sockaddr_swift {
    int count;
    struct swift_dest dests[0];
};

#ifdef __KERNEL__
struct swifthdr {
	uint8_t src;
	uint8_t dst;
	__be16 len;
};
#endif

#endif
