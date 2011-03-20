/*
 * Header for all swift test functions.
 */

#ifndef TEST_SW_H_
#define TEST_SW_H_		1

#ifdef __cplusplus
extern "C" {
#endif

void test_dummy(void);
void socket_test_suite(void);
void bind_test_suite(void);
void getsockname_test_suite(void);
void getsockopt_test_suite(void);
void sendto_test_suite(void);
void recvfrom_test_suite(void);
void sendmsg_test_suite(void);
void recvmsg_test_suite(void);
void shutdown_test_suite(void);
void close_test_suite(void);

/* TODO: fill with test function headers. */

#ifdef __cplusplus
}
#endif

#endif
