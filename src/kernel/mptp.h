#ifndef _MPTP_H
#define _MPTP_H

#define IPPROTO_MPTP 137

#define MIN_MPTP_PORT 1
#define MAX_MPTP_PORT 65536

#ifndef __KERNEL__
#include <inttypes.h>
#endif

struct mptp_dest {
    uint32_t addr;
    uint16_t port;
};

struct sockaddr_mptp {
    int count;
    struct mptp_dest dests[0];
};

#ifdef __KERNEL__
struct mptphdr {
	uint16_t src;
	uint16_t dst;
	__be16 len;
};
#endif

#endif
