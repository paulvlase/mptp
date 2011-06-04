/*
 * swift implementation of syscall API
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
#include "swift_list.h"
#include "debug.h"
#include "util.h"

/*
 * Add new socket to list. Called by sw_socket "syscall".
 */

struct sock_list *list_add_socket(int s)
{
	struct sock_list *ptr = malloc(sizeof(*ptr));
	if (ptr == NULL)
		return NULL;

	ptr->next = &sock_list_head;
	ptr->prev = sock_list_head.prev;
	sock_list_head.prev->next = ptr;
	sock_list_head.prev = ptr;
	ptr->s = s;

	return ptr;
}

/*
 * Bind socket to given address. Called by sw_bind "syscall".
 */

struct sock_list *list_update_socket_address(int s, __CONST_SOCKADDR_ARG addr)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s) {
			memcpy(&ptr->addr, addr, sizeof(ptr->addr));
			ptr->bind_state = STATE_BOUND;
			return ptr;
		}

	return NULL;
}

/*
 * Get list element containing socket s. Called by sw_send* "syscalls".
 */

struct sock_list *list_elem_from_socket(int s)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s)
			return ptr;

	return NULL;
}

/*
 * Get list element containing address addr. Called by sw_bind "syscall".
 */

struct sock_list *list_elem_from_address(__CONST_SOCKADDR_ARG addr)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next) {
		dprintf("socket address to be checked\n");
		if (ptr->bind_state == STATE_NOTBOUND)
			continue;
		dprintf("bound socket address to be checked\n");
		if (memcmp(&ptr->addr, addr, sizeof(addr)) == 0)
			return ptr;
	}

	return NULL;
}

/*
 * Unlink socket from list. Called by list_remove_socket.
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
 * Remove socket from list. Called by sw_close "syscall".
 */

int list_remove_socket(int s)
{
	struct sock_list *ptr;

	ptr = list_unlink_socket(s);
	if (ptr == NULL)
		return -1;

	free(ptr);
	return 0;
}

/*
 * Check if a socket is bound.
 */
int list_socket_is_bound(int s)
{
	struct sock_list *ptr;

	for (ptr = sock_list_head.next; ptr != &sock_list_head; ptr = ptr->next)
		if (ptr->s == s) {
			if (ptr->bind_state == STATE_BOUND)
				return 1;
			break;
		}

	return 0;
}
