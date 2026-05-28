#include "test_runner.h"
#include "seccomp.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>

/* stub state */
static int g_prctl_called;
static int g_prctl_ret;
static int g_prctl_option;
static int g_prctl_secmode;
static int g_prctl_errno;

/* stub */
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
  (void)arg3;
  (void)arg4;
  (void)arg5;
  g_prctl_called = 1;
  g_prctl_option = option;
  g_prctl_secmode = (int)arg2;
  if (g_prctl_errno)
    errno = g_prctl_errno;
  return g_prctl_ret;
}

static void reset_stubs(void)
{
  g_prctl_called = 0;
  g_prctl_ret = 0;
  g_prctl_option = 0;
  g_prctl_secmode = 0;
  g_prctl_errno = 0;
}

static void test_seccomp_installed(void)
{
  reset_stubs();
  g_prctl_ret = 0;

  ASSERT_INT_EQ(install_seccomp(0), 0);
  ASSERT_INT_EQ(g_prctl_called, 1);
}

static void test_seccomp_not_available(void)
{
  reset_stubs();
  g_prctl_ret = -1;
  g_prctl_errno = EINVAL;

  ASSERT_INT_EQ(install_seccomp(0), -1);
  ASSERT_INT_EQ(g_prctl_called, 1);
}

/* ---- test group ---- */

TEST_GROUP(seccomp)
{
TEST(test_seccomp_installed), TEST(test_seccomp_not_available), END_TEST};

int main(void)
{
  int passed = 0;
  int failed = 0;
  int ti;

  printf("seccomp:\n");
  for (ti = 0; seccomp_tests[ti].fn != NULL; ti++) {
    printf("  %s ... ", seccomp_tests[ti].name);
    seccomp_tests[ti].fn();
    printf("OK\n");
    passed++;
  }

  printf("\n%d passed, %d failed\n", passed, failed);
  return failed;
}
