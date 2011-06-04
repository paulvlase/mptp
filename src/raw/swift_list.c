/*
 * Linked list management for sockets
 *
 * Use sock_list structure to store information about sockets. Use functions
 * to add, remove, find and update information in list.
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
struct sock_list {
	int s;
	struct sockaddr addr;
	enum sock_bind_state bind_state;
	struct sock_list *next;
	struct sock_list *prev;
};

/* socket management list head */
static struct sock_list sock_list_head = {
	.next = &sock_list_head,
	.prev = &sock_list_head
};

/*
 * Find socket in socket management list.
 */

static struct sock_list *list_get_link(int s)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s)
			return ptr;

	return NULL;
}

/*
 * Find socket in socket management list by address.
 */

static struct sock_list *list_get_link_by_address(const struct sockaddr *addr)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (memcmp(addr, &ptr->addr, sizeof(*addr)) == 0)
			return ptr;

	return NULL;
}

/*
 * Unlink socket from list. Called by sm_del.
 */

static void list_unlink(struct sock_list *ptr)
{
	ptr->next->prev = ptr->prev;
	ptr->prev->next = ptr->next;
	ptr->next = ptr;
	ptr->prev = ptr;
}

/*
 * Link socket to list. Add socket to tail of list.
 */

static void list_link(struct sock_list *ptr)
{
	ptr->next = &sock_list_head;
	ptr->prev = sock_list_head.prev;
	sock_list_head.prev->next = ptr;
	sock_list_head.prev = ptr;
}

/*
 * Add new socket to list. Called by sw_socket "syscall".
 */

int sm_add(int s)
{
	struct sock_list *ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return -1;

	ptr->s = s;
	list_link(ptr);

	return 0;
}

/*
 * Bind socket to given address. Called by sw_bind "syscall".
 */

int sm_update_address(int s, const struct sockaddr *addr)
{
	struct sock_list *ptr;

	ptr = list_get_link(s);
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
	struct sock_list *ptr;

	ptr = list_get_link(s);
	if (ptr == NULL)
		return -1;

	list_unlink(ptr);
	free(ptr);

	return 0;
}

/*
 * Check if a socket is bound.
 */

int sm_is_bound(int s)
{
	struct sock_list *ptr;

	ptr = list_get_link(s);
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
	struct sock_list *ptr;
	
	ptr = list_get_link(s);
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
	struct sock_list *ptr;

	ptr = list_get_link(s);
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
	struct sock_list *ptr;

	ptr = list_get_link_by_address(addr);
	if (ptr == NULL)
		return 0;

	return 1;
}

/*
 * Find socket address.
 */

struct sockaddr *sm_get_address(int s)
{
	struct sock_list *ptr;

	ptr = list_get_link(s);
	if (ptr == NULL)
		return NULL;

	return &ptr->addr;
}
