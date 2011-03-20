#ifndef __SOCK_LIST

#define __SOCK_LIST

enum sock_rw_state {
	STATE_NO_SHUT,
	STATE_SHUT_RD,
	STATE_SHUT_WR,
	STATE_SHUT_RDWR
};

enum sock_bind_state {
	STATE_NOTBOUND,
	STATE_BOUND
};

/* socket management structure */
struct sock_list {
	int s;
	struct sockaddr_sw addr;
	enum sock_rw_state rw_state;
	enum sock_bind_state bind_state;
	struct sock_list *next;
	struct sock_list *prev;
};

static struct sock_list sock_list_head = {
	.next = &sock_list_head,
	.prev = &sock_list_head
};

/*
 * Add new socket to list. Called by sw_socket "syscall".
 */
struct sock_list *list_add_socket(int s);

/*
 * Bind socket to given address. Called by sw_bind "syscall".
 */

struct sock_list *list_update_socket_address(int s, __CONST_SOCKADDR_ARG addr);

/*
 * Get list element containing socket s. Called by sw_send* "syscalls".
 */

struct sock_list *list_elem_from_socket(int s);

/*
 * Get list element containing address addr. Called by sw_bind "syscall".
 */

struct sock_list *list_elem_from_address(__CONST_SOCKADDR_ARG addr);

/*
 * Remove socket from list. Called by sw_close "syscall".
 */

int list_remove_socket(int s);

/*
 * Check if a socket is bound.
 */
int list_socket_is_bound(int s);

#endif
