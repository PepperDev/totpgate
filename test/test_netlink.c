#include "test_runner.h"
#include "netlink.h"

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

/*
 * Stub overrides for syscalls used by netlink.c.
 * These are linked in place of libc's versions.
 */

/* capture the last request */
static struct {
  struct nlmsghdr hdr;
  char raw[4096];
  size_t len;
} g_last_req;

static int g_fake_fd = 5;
static int g_close_count;
static int g_recv_mode;         /* 0 = ack, 1 = echo */
static uint64_t g_echo_handle;

/* ---- syscall stubs ---- */

int socket(int domain, int type, int protocol)
{
  (void)domain;
  (void)type;
  (void)protocol;
  return g_fake_fd;
}

int close(int fd)
{
  (void)fd;
  g_close_count++;
  return 0;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *addr, socklen_t addrlen)
{
  (void)fd;
  (void)flags;
  (void)addr;
  (void)addrlen;

  if (len > sizeof(g_last_req.raw)) {
    len = sizeof(g_last_req.raw);
  }
  memcpy(&g_last_req.hdr, buf, len < sizeof(struct nlmsghdr) ? len : sizeof(struct nlmsghdr));
  if (len > 0) {
    memcpy(g_last_req.raw, buf, len);
  }
  g_last_req.len = len;
  return (ssize_t) len;
}

ssize_t recv(int fd, void *buf, size_t len, int flags)
{
  struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
  struct nfgenmsg *nfg;
  struct nlattr *nla;
  uint32_t seq;
  size_t off;

  (void)fd;
  (void)flags;

  memset(buf, 0, len);
  seq = g_last_req.hdr.nlmsg_seq;

  if (g_recv_mode == 1) {
    /* echo-style response with handle */
    nlh->nlmsg_len = (uint32_t) NLMSG_LENGTH(sizeof(struct nfgenmsg)) + NLA_HDRLEN + 8
        + NLA_HDRLEN + 10 + NLA_HDRLEN + 6;
    nlh->nlmsg_type = g_last_req.hdr.nlmsg_type;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = 0;
    nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    nfg->nfgen_family = AF_INET;
    nfg->version = NFNETLINK_V0;
    nfg->res_id = 0;

    off = NLMSG_LENGTH(sizeof(struct nfgenmsg));

    /* handle attribute */
    nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(off));
    nla->nla_len = NLA_HDRLEN + 8;
    nla->nla_type = NFTA_RULE_HANDLE;
    memcpy((char *)nla + NLA_HDRLEN, &g_echo_handle, 8);
    off = NLMSG_ALIGN(off) + NLA_ALIGN(NLA_HDRLEN + 8);

    nlh->nlmsg_len = (uint32_t) (NLMSG_ALIGN(off));

    return (ssize_t) nlh->nlmsg_len;
  }

  /* default: ACK response */
  nlh->nlmsg_len = NLMSG_LENGTH((uint32_t) sizeof(int));
  nlh->nlmsg_type = NLMSG_ERROR;
  nlh->nlmsg_seq = seq;
  *(int *)NLMSG_DATA(nlh) = 0;
  return (ssize_t) nlh->nlmsg_len;
}

/* ---- test helpers ---- */

static void set_recv_ack(void)
{
  g_recv_mode = 0;
}

static void set_recv_echo(uint64_t handle)
{
  g_recv_mode = 1;
  g_echo_handle = handle;
}

/* ---- tests ---- */

static void test_init_ok(void)
{
  int ret;

  g_fake_fd = 5;
  g_close_count = 0;
  set_recv_ack();
  ret = netlink_init();
  ASSERT_INT_EQ(ret, 0);
}

static void test_flush_chain_ok(void)
{
  int ret;

  set_recv_ack();
  ret = netlink_flush_chain();
  ASSERT_INT_EQ(ret, 0);
}

static void test_add_established_ok(void)
{
  int ret;

  set_recv_ack();
  ret = netlink_add_established_rule();
  ASSERT_INT_EQ(ret, 0);
}

static void test_add_default_drop_ok(void)
{
  int ret;

  /* echo mode so handle gets parsed */
  set_recv_echo(42);
  ret = netlink_add_default_drop(22);
  ASSERT_INT_EQ(ret, 0);
}

static void test_rule_insert_ok(void)
{
  uint64_t h;

  set_recv_echo(99);
  h = netlink_rule_insert(0xc0a80101, 22);
  ASSERT_TRUE(h != 0);
  ASSERT_INT_EQ((int)h, 99);
}

static void test_rule_delete_ok(void)
{
  int ret;

  set_recv_ack();
  ret = netlink_rule_delete(99);
  ASSERT_INT_EQ(ret, 0);
}

static void test_cleanup(void)
{
  g_close_count = 0;
  set_recv_ack();
  netlink_cleanup();
  ASSERT_TRUE(g_close_count > 0);
}

/* ---- group ---- */

TEST_GROUP(netlink)
{
TEST(test_init_ok),
      TEST(test_flush_chain_ok),
      TEST(test_add_established_ok),
      TEST(test_add_default_drop_ok),
      TEST(test_rule_insert_ok), TEST(test_rule_delete_ok), TEST(test_cleanup), END_TEST};

int main(void)
{
  int passed = 0;
  int failed = 0;
  int ti;

  printf("netlink:\n");
  for (ti = 0; netlink_tests[ti].fn != NULL; ti++) {
    printf("  %s ... ", netlink_tests[ti].name);
    /* reset state before each test */
    memset(&g_last_req, 0, sizeof(g_last_req));
    g_fake_fd = 5;
    g_close_count = 0;
    g_recv_mode = 0;
    g_echo_handle = 0;
    netlink_tests[ti].fn();
    printf("OK\n");
    passed++;
  }

  printf("\n%d passed, %d failed\n", passed, failed);
  return failed;
}
