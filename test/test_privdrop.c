#include "test_runner.h"
#include "privdrop.h"

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

/* ---- stub state ---- */

static int g_stub_uid;
static int g_stub_euid;
static int g_stub_pwnam_fail;
static int g_stub_grnam_fail;
static int g_stub_setgroups_fail;
static int g_stub_setgid_fail;
static int g_stub_setuid_fail;
static int g_stub_prctl_fail;
static int g_stub_setgroups_called;
static int g_stub_setgid_called;
static int g_stub_setuid_called;
static int g_stub_prctl_called;

/* ---- stubs for libc functions ---- */

uid_t getuid(void)
{
  return (uid_t) g_stub_uid;
}

uid_t geteuid(void)
{
  return (uid_t) g_stub_euid;
}

struct passwd {
  char *pw_name;
  uid_t pw_uid;
  gid_t pw_gid;
};

struct passwd *getpwnam(const char *name)
{
  static struct passwd pw;
  (void)name;
  if (g_stub_pwnam_fail)
    return NULL;
  pw.pw_uid = 999;
  pw.pw_gid = 999;
  return &pw;
}

struct group {
  char *gr_name;
  gid_t gr_gid;
};

struct group *getgrnam(const char *name)
{
  static struct group gr;
  (void)name;
  if (g_stub_grnam_fail)
    return NULL;
  gr.gr_gid = 999;
  return &gr;
}

int setgroups(size_t size, const gid_t *list)
{
  (void)size;
  (void)list;
  g_stub_setgroups_called = 1;
  return g_stub_setgroups_fail ? -1 : 0;
}

int setgid(gid_t gid)
{
  (void)gid;
  g_stub_setgid_called = 1;
  return g_stub_setgid_fail ? -1 : 0;
}

int setuid(uid_t uid)
{
  (void)uid;
  g_stub_setuid_called = 1;
  return g_stub_setuid_fail ? -1 : 0;
}

int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
  (void)option;
  (void)arg2;
  (void)arg3;
  (void)arg4;
  (void)arg5;
  g_stub_prctl_called = 1;
  return g_stub_prctl_fail ? -1 : 0;
}

/* ---- tests ---- */

static void reset_stubs(void)
{
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_pwnam_fail = 0;
  g_stub_grnam_fail = 0;
  g_stub_setgroups_fail = 0;
  g_stub_setgid_fail = 0;
  g_stub_setuid_fail = 0;
  g_stub_prctl_fail = 0;
  g_stub_setgroups_called = 0;
  g_stub_setgid_called = 0;
  g_stub_setuid_called = 0;
  g_stub_prctl_called = 0;
}

static void test_drop_non_root(void)
{
  reset_stubs();
  g_stub_uid = 1000;
  g_stub_euid = 1000;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), 0);
  ASSERT_INT_EQ(g_stub_setgroups_called, 0);
}

static void test_drop_root_success(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), 0);
  ASSERT_INT_EQ(g_stub_setgroups_called, 1);
  ASSERT_INT_EQ(g_stub_setgid_called, 1);
  ASSERT_INT_EQ(g_stub_setuid_called, 1);
  ASSERT_INT_EQ(g_stub_prctl_called, 1);
}

static void test_drop_unknown_user(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_pwnam_fail = 1;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), -1);
}

static void test_drop_unknown_group(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_grnam_fail = 1;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), -1);
}

static void test_drop_setgroups_fail(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_setgroups_fail = 1;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), -1);
}

static void test_drop_setgid_fail(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_setgid_fail = 1;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), -1);
}

static void test_drop_setuid_fail(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_setuid_fail = 1;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), -1);
}

static void test_drop_prctl_fail(void)
{
  reset_stubs();
  g_stub_uid = 0;
  g_stub_euid = 0;
  g_stub_prctl_fail = 1;

  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 0), -1);
}

/* ---- test group ---- */

TEST_GROUP(privdrop)
{
TEST(test_drop_non_root),
      TEST(test_drop_root_success),
      TEST(test_drop_unknown_user),
      TEST(test_drop_unknown_group),
      TEST(test_drop_setgroups_fail),
      TEST(test_drop_setgid_fail), TEST(test_drop_setuid_fail), TEST(test_drop_prctl_fail), END_TEST};

int main(void)
{
  int passed = 0;
  int failed = 0;
  int ti;

  printf("privdrop:\n");
  for (ti = 0; privdrop_tests[ti].fn != NULL; ti++) {
    printf("  %s ... ", privdrop_tests[ti].name);
    privdrop_tests[ti].fn();
    printf("OK\n");
    passed++;
  }

  printf("\n%d passed, %d failed\n", passed, failed);
  return failed;
}
