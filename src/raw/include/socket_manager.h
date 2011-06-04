/*
 * Socket management interface.
 *
 * 2011, Razvan Deaconescu, razvan.deaconescu@cs.pub.ro
 */

#ifndef SOCKET_MANAGER_H_
#define SOCKET_MANAGER_H_	1

#include <netinet/in.h>

/*
 * Add new socket to list. Called by sw_socket "syscall".
 */

int sm_add(int s);

/*
 * Bind socket to given address. Called by sw_bind "syscall".
 */

int sm_update_address(int s, const struct sockaddr *addr);

/*
 * Remove socket from list. Called by sw_close "syscall".
 */

int sm_del(int s);

/*
 * Check if a socket is bound.
 */

int sm_is_bound(int s);

/*
 * Mark socket as bound.
 */

int sm_mark_bound(int s);

/*
 * Mark socket as unbound.
 */

int sm_mark_unbound(int s);

/*
 * Check if adress is asociated with a given socket.
 */

int sm_address_exists(const struct sockaddr *addr);

/*
 * Find socket address.
 */

struct sockaddr *sm_get_address(int s);

#endif
