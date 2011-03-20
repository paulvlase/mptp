/*
 * Dummy test functions.
 */

#include "test.h"

static void dummy_1_eq_1(void);
static void dummy_1_neq_0(void);

void test_dummy(void) 
{
	start_suite();
	dummy_1_eq_1();
	dummy_1_neq_0();
}

static void dummy_1_eq_1(void)
{
	test(1 == 1);
}

static void dummy_1_neq_0(void)
{
	test(1 != 0);
}
