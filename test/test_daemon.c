#include "test_runner.h"
#include "encode.h"
#include "netlink.h"
#include "udp.h"
#include "auth.h"
#include "totp.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* struct definitions matching main.c */
struct config {
  uint16_t port;
  uint16_t target_port;
  unsigned char secret[256];
  size_t secret_len;
  uint32_t timeout;
  int foreground;
  int test_mode;
};

struct daemon {
  struct config *cfg;
  int udp_fd;
  int epoll_fd;
  int signal_fd;
  time_t last_prune;
};

/* declare daemon functions from main.c */

int daemon_setup(struct daemon *d, struct config *cfg);
int daemon_process(struct daemon *d);
void daemon_cleanup(struct daemon *d);
int daemon_run(struct config *cfg);
int parse_args(struct config *cfg, int argc, char *argv[]);

/* import mock globals */
extern int g_nl_init_ret;
extern int g_nl_flush_ret;
extern int g_nl_est_ret;
extern int g_nl_drop_ret;
extern uint16_t g_nl_drop_port;
extern int g_nl_cleanup_called;
extern uint64_t g_nl_insert_return;
extern uint32_t g_nl_insert_ip;
extern int g_udp_open_ret;
extern uint16_t g_udp_open_port;
extern unsigned char g_udp_recv_buf[256];
extern size_t g_udp_recv_len;
extern uint32_t g_udp_recv_src_ip;
extern uint16_t g_udp_recv_src_port;

extern void mock_netlink_reset(void);
extern void mock_udp_reset(void);

/* ---- parse_args tests ---- */

static void test_parse_minimal(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP", NULL };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 3, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.port, 2222);
  ASSERT_INT_EQ((int)cfg.target_port, 22);
  ASSERT_INT_EQ((int)cfg.timeout, 30);
  ASSERT_INT_EQ(cfg.foreground, 0);
  ASSERT_TRUE(cfg.secret_len > 0);
}

static void test_parse_all_options(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--port", "9999", "--target-port", "443",
    "--secret", "hex:48656c6c6f", "--timeout", "120",
    "--foreground", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 10, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.port, 9999);
  ASSERT_INT_EQ((int)cfg.target_port, 443);
  ASSERT_INT_EQ((int)cfg.timeout, 120);
  ASSERT_INT_EQ(cfg.foreground, 1);
  ASSERT_INT_EQ((int)cfg.secret_len, 5);
}

static void test_parse_missing_secret(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", NULL };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 1, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_bad_port(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--port", "99999", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_bad_target_port(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--target-port", "99999", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_bad_timeout(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--timeout", "99999", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_invalid_secret(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "hex:ZZZZ", NULL };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 3, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_unknown_option(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--bogus", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 4, argv);
  ASSERT_INT_EQ(ret, -1);
}

/* ---- daemon_setup tests ---- */

static void test_setup_success(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_TRUE(d.udp_fd >= 0);
  ASSERT_TRUE(d.epoll_fd >= 0);
  ASSERT_TRUE(d.signal_fd >= 0);
  ASSERT_INT_EQ((int)g_udp_open_port, 2222);

  daemon_cleanup(&d);
}

static void test_setup_netlink_init_fail(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();
  g_nl_init_ret = -1;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, -1);
}

static void test_setup_netlink_est_fail(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();
  g_nl_est_ret = -1;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, -1);
}

static void test_setup_netlink_drop_fail(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();
  g_nl_drop_ret = -1;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, -1);
}

static void test_setup_udp_open_fail(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();
  g_udp_open_ret = -1;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, -1);
}

static void test_setup_flush_fail(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();
  g_nl_flush_ret = -1;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_TRUE(d.udp_fd >= 0);

  daemon_cleanup(&d);
}

static void test_setup_foreground_off(void)
{
  struct config cfg;
  struct daemon d;

  mock_netlink_reset();
  mock_udp_reset();

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 0;

  int ret = daemon_setup(&d, &cfg);
  ASSERT_INT_EQ(ret, 0);

  daemon_cleanup(&d);
}

/* ---- daemon_run tests ---- */

static void test_daemon_run_test_mode(void)
{
  struct config cfg;

  mock_netlink_reset();
  mock_udp_reset();

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  cfg.test_mode = 1;

  int ret = daemon_run(&cfg);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ(g_nl_cleanup_called, 1);
}

static void test_daemon_run_setup_fail(void)
{
  struct config cfg;

  mock_netlink_reset();
  mock_udp_reset();
  g_nl_init_ret = -1;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  cfg.test_mode = 1;

  int ret = daemon_run(&cfg);
  ASSERT_INT_EQ(ret, 1);
}

static void test_daemon_process_packet(void)
{
  struct config cfg;
  struct daemon d;
  unsigned char test_secret[20];
  uint32_t token;
  uint64_t counter;
  char pkt[32];
  size_t pkt_len;
  int i;
  int s;
  struct sockaddr_in addr;

  mock_netlink_reset();
  mock_udp_reset();

  for (i = 0; i < 20; i++) {
    test_secret[i] = (unsigned char)(i + 1);
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  memcpy(cfg.secret, test_secret, 20);

  /* open daemon (binds real UDP socket to port 2222) */
  ASSERT_INT_EQ(daemon_setup(&d, &cfg), 0);

  /* compute current TOTP and stage it in mock recv buffer */
  counter = (uint64_t) (time(NULL) / 30);
  token = totp_generate(test_secret, 20, counter, 6);
  pkt_len = (size_t)snprintf(pkt, sizeof(pkt), "%06u", (unsigned)token);
  g_udp_recv_len = pkt_len;
  memcpy(g_udp_recv_buf, pkt, pkt_len);
  g_udp_recv_src_ip = 0x01010101;
  g_udp_recv_src_port = 54321;

  /* send a real UDP packet to wake up epoll (actual data ignored by mock) */
  s = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(s >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(2222);
  addr.sin_addr.s_addr = htonl(0x7f000001);
  sendto(s, pkt, 1, 0, (struct sockaddr *)&addr, sizeof(addr));
  close(s);

  /* process — epoll picks up the real packet, mock udp_recv returns the token */
  ASSERT_INT_EQ(daemon_process(&d), 0);

  /* verify the IP we injected via mock reached netlink_rule_insert */
  ASSERT_INT_EQ((int)g_nl_insert_ip, 0x01010101);

  daemon_cleanup(&d);
  auth_replay_reset();
}

static void test_daemon_malformed_packet(void)
{
  struct config cfg;
  struct daemon d;
  unsigned char test_secret[20];
  int i;
  int s;
  struct sockaddr_in addr;

  mock_netlink_reset();
  mock_udp_reset();

  for (i = 0; i < 20; i++) {
    test_secret[i] = (unsigned char)(i + 1);
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2223;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  memcpy(cfg.secret, test_secret, 20);

  ASSERT_INT_EQ(daemon_setup(&d, &cfg), 0);

  /* stage malformed data (non-numeric) in mock recv buffer */
  g_udp_recv_len = 6;
  memcpy(g_udp_recv_buf, "abcdef", 6);
  g_udp_recv_src_ip = 0x01010101;
  g_udp_recv_src_port = 54321;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(s >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(2223);
  addr.sin_addr.s_addr = htonl(0x7f000001);
  sendto(s, "x", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
  close(s);

  ASSERT_INT_EQ(daemon_process(&d), 0);

  /* verify netlink_insert was NOT called (ip should be 0) */
  ASSERT_INT_EQ((int)g_nl_insert_ip, 0);

  daemon_cleanup(&d);
}

static void test_daemon_truncated_packet(void)
{
  struct config cfg;
  struct daemon d;
  unsigned char test_secret[20];
  int i;
  int s;
  struct sockaddr_in addr;

  mock_netlink_reset();
  mock_udp_reset();

  for (i = 0; i < 20; i++) {
    test_secret[i] = (unsigned char)(i + 1);
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2224;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  memcpy(cfg.secret, test_secret, 20);

  ASSERT_INT_EQ(daemon_setup(&d, &cfg), 0);

  /* stage truncated packet (only 3 digits — too short) */
  g_udp_recv_len = 3;
  memcpy(g_udp_recv_buf, "123", 3);
  g_udp_recv_src_ip = 0x02020202;
  g_udp_recv_src_port = 12345;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(s >= 0);
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(2224);
  addr.sin_addr.s_addr = htonl(0x7f000001);
  sendto(s, "x", 1, 0, (struct sockaddr *)&addr, sizeof(addr));
  close(s);

  ASSERT_INT_EQ(daemon_process(&d), 0);

  /* verify netlink_insert was NOT called */
  ASSERT_INT_EQ((int)g_nl_insert_ip, 0);

  daemon_cleanup(&d);
}

/* ---- auth_replay tests for prune ---- */

static void test_prune_expired(void)
{
  auth_replay_reset();

  auth_record_seq(100, 0x01010101);
  auth_record_seq(200, 0x02020202);

  auth_replay_prune(time(NULL) + 10, 5);
  ASSERT_INT_EQ(auth_seen_before(100, 0x01010101), 0);
  ASSERT_INT_EQ(auth_seen_before(200, 0x02020202), 0);
}

static void test_prune_fresh_kept(void)
{
  auth_replay_reset();

  auth_record_seq(100, 0x03030303);

  auth_replay_prune(time(NULL), 3600);
  ASSERT_INT_EQ(auth_seen_before(100, 0x03030303), -1);
}

/* ---- test group ---- */

TEST_GROUP(daemon)
{
TEST(test_parse_minimal),
      TEST(test_parse_all_options),
      TEST(test_parse_missing_secret),
      TEST(test_parse_bad_port),
      TEST(test_parse_bad_target_port),
      TEST(test_parse_bad_timeout),
      TEST(test_parse_invalid_secret),
      TEST(test_parse_unknown_option),
      TEST(test_setup_success),
      TEST(test_setup_netlink_init_fail),
      TEST(test_setup_netlink_est_fail),
      TEST(test_setup_netlink_drop_fail),
      TEST(test_setup_udp_open_fail),
      TEST(test_setup_flush_fail),
      TEST(test_setup_foreground_off),
      TEST(test_daemon_run_test_mode),
      TEST(test_daemon_run_setup_fail),
      TEST(test_daemon_process_packet), TEST(test_daemon_malformed_packet),
      TEST(test_daemon_truncated_packet), TEST(test_prune_expired), TEST(test_prune_fresh_kept), END_TEST};

#ifdef BUILD_DAEMON_TEST_MAIN
int main(void)
{
  int passed = 0;
  int failed = 0;
  int ti;

  printf("daemon:\n");
  for (ti = 0; daemon_tests[ti].fn != NULL; ti++) {
    printf("  %s ... ", daemon_tests[ti].name);
    daemon_tests[ti].fn();
    printf("OK\n");
    passed++;
  }

  printf("\n%d passed, %d failed\n", passed, failed);
  return failed;
}
#endif
