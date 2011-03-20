/*
 * generic test suite
 *
 * test macros and headers
 */

#ifndef TEST_H_
#define TEST_H_		1

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>

/*
 * uncommend EXIT_IF_FAIL macro in order to stop test execution
 * at first failed test
 */

/*#define EXIT_IF_FAIL	1*/

#if defined (EXIT_IF_FAIL)
#define test_do_fail()			\
	do {				\
		printf("failed\n");	\
		exit(EXIT_FAILURE);	\
	} while (0)
#else
#define test_do_fail()			\
	printf("failed\n")
#endif

#define test_do_pass()			\
	printf("passed\n")

#define test(test)						\
	do {							\
		size_t i;					\
		int t = (test);					\
								\
		printf("%s", __FUNCTION__);			\
		fflush(stdout);					\
								\
		for (i = 0; i < 60 - strlen(__FUNCTION__); i++)	\
			putchar('.');				\
								\
		if (!t)						\
		        test_do_fail();				\
		else						\
			test_do_pass();				\
								\
		fflush(stdout);					\
	} while (0)

#define start_suite()			\
	do {						\
			printf("\n==== Starting %s ====\n", __FUNCTION__); \
	} while (0)
#ifdef __cplusplus
}
#endif

#endif
