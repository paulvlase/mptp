/*
 * Array management for sockets
 *
 * Use an array similar to a descriptor table to store information about
 * sockets. Use functions to add, remove, find and update information.
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
#include "socket_manager.h"
#include "debug.h"
#include "util.h"

enum sock_bind_state {
	STATE_NOTBOUND,
	STATE_BOUND
};

/* socket management structure */
struct sock {
	int s;
	struct sockaddr addr;
	enum sock_bind_state bind_state;
};

/*
 * Socket management array
 * Size is assumed size of descriptor table. Socket descriptor is an array
 * index.
 */
#define ARRAY_SIZE	1024
static struct sock *sock_array[ARRAY_SIZE];

/*
 * Find socket in socket management array.
 */

static struct sock *array_get_sock(int s)
{
	if (s < 0 || s >= ARRAY_SIZE)
		return NULL;

	return sock_array[s];
}

/*
 * Find socket in socket management array by address.
 */

static struct sock *array_get_sock_by_address(const struct sockaddr *addr)
{
	struct sock *ptr;
	int i;

	for (i = 0; i < ARRAY_SIZE; i++) {
		ptr = sock_array[i];
		if (ptr == NULL)
			continue;
		if (memcmp(addr, &ptr->addr, sizeof(*addr)) == 0)
			return ptr;
	}

	return NULL;
}

/*
 * Add new socket to list. Called by sw_socket "syscall".
 */

int sm_add(int s)
{
	struct sock *ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return -1;

	ptr->s = s;
	sock_array[s] = ptr;

	return 0;
}

/*
 * Bind socket to given address. Called by sw_bind "syscall".
 */

int sm_update_address(int s, const struct sockaddr *addr)
{
	struct sock *ptr;

	ptr = array_get_sock(s);
	if (ptr == NULL)
		return -1;

	memcpy(&ptr->addr, addr, sizeof(ptr->addr));

	return 0;
}

/*
 * Remove socket from list. Called by sw_close "syscall".
 */

int sm_del(int s)
{
	struct sock *ptr;

	ptr = array_get_sock(s);
	if (ptr == NULL)
		return -1;

	sock_array[s] = NULL;
	free(ptr);

	return 0;
}

/*
 * Check if a socket is bound.
 */

int sm_is_bound(int s)
{
	struct sock *ptr;

	ptr = array_get_sock(s);
	if (ptr == NULL)
		return 0;

	if (ptr->bind_state == STATE_BOUND)
		return 1;

	return 0;
}

/*
 * Mark socket as bound.
 */

int sm_mark_bound(int s)
{
	struct sock *ptr;

	ptr = array_get_sock(s);
	if (ptr == NULL)
		return -1;

	ptr->bind_state = STATE_BOUND;

	return 0;
}

/*
 * Mark socket as unbound.
 */

int sm_mark_unbound(int s)
{
	struct sock *ptr;

	ptr = array_get_sock(s);
	if (ptr == NULL)
		return -1;

	ptr->bind_state = STATE_NOTBOUND;

	return 0;
}

/*
 * Check if adress is asociated with a given socket.
 */

int sm_address_exists(const struct sockaddr *addr)
{
	struct sock *ptr;

	ptr = array_get_sock_by_address(addr);
	if (ptr == NULL)
		return 0;

	return 1;
}

/*
 * Find socket address.
 */

struct sockaddr *sm_get_address(int s)
{
	struct sock *ptr;

	ptr = array_get_sock(s);
	if (ptr == NULL)
		return NULL;

	return &ptr->addr;
}
