/*
 * Header for all swift test functions.
 */

#ifndef TEST_SW_H_
#define TEST_SW_H_		1

#ifdef __cplusplus
extern "C" {
#endif

void dummy_1_eq_1(void);
void dummy_1_neq_0(void);
void socket_dummy(void);
void bind_dummy(void);
void getsockname_dummy(void);
void sendto_dummy(void);
void recvfrom_dummy(void);
void sendmsg_dummy(void);
void recvmsg_dummy(void);
void shutdown_dummy(void);
void close_dummy(void);

/* TODO: fill with test function headers. */

#ifdef __cplusplus
}
#endif

#endif
