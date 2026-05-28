#include "test_runner.h"
#include "encode.h"
#include "netlink.h"
#include "udp.h"
#include "auth.h"
#include "totp.h"
#include "ratelimit.h"

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
  char user[32];
  char group[32];
  char secret_file[4096];
  int foreground;
  int test_mode;
  struct rate_limit_cfg rate_limit;
};

struct daemon {
  struct config *cfg;
  int udp_fd;
  int epoll_fd;
  int signal_fd;
  int maxevents;
  time_t last_prune;
};

/* declare daemon functions from main.c */

int daemon_setup(struct daemon *d, struct config *cfg);
int daemon_process(struct daemon *d);
void daemon_cleanup(struct daemon *d);
int daemon_run(struct config *cfg);
int parse_args(struct config *cfg, int argc, char *argv[]);
int drop_privileges(const char *user, const char *group, int foreground);
int read_secret_file(const char *path, struct config *cfg);

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

extern int g_udp_recv_done;

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

static void test_parse_min_block(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--min-block", "600", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.rate_limit.min_block, 600);
}

static void test_parse_min_block_bad(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--min-block", "99999", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_max_block(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--max-block", "7200", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.rate_limit.max_block, 7200);
}

static void test_parse_rate_limit(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--rate-limit", "10/120", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.rate_limit.max_fails, 10);
  ASSERT_INT_EQ((int)cfg.rate_limit.window, 120);
}

static void test_parse_rate_limit_bad(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--rate-limit", "abc", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_user(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--user", "daemon", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_STREQ(cfg.user, "daemon");
}

static void test_parse_group(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--group", "daemon", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_STREQ(cfg.group, "daemon");
}

static void test_parse_secret_file(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret-file", "/etc/totpgated.key", NULL };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  int ret = parse_args(&cfg, 3, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_STREQ(cfg.secret_file, "/etc/totpgated.key");
}

static void test_parse_secret_file_too_long(void)
{
  struct config cfg;
  char longpath[4100];
  char *argv[3];

  memset(longpath, 'a', 4096);
  longpath[4096] = '\0';
  argv[0] = "totpgated";
  argv[1] = "--secret-file";
  argv[2] = longpath;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  ASSERT_INT_EQ(parse_args(&cfg, 3, argv), -1);
}

static void test_parse_secret_mutual_exclusive(void)
{
  struct config cfg;
  char *argv[] = { "totpgated", "--secret", "JBSWY3DPEHPK3PXP",
    "--secret-file", "/tmp/secret", NULL
  };

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  optind = 0;
  ASSERT_INT_EQ(parse_args(&cfg, 5, argv), -1);
}

static void test_read_secret_file_ok(void)
{
  struct config cfg;
  const char *path = "/tmp/totpgate_test_secret";
  FILE *f;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;

  f = fopen(path, "w");
  ASSERT_TRUE(f != NULL);
  fprintf(f, "JBSWY3DPEHPK3PXP\n");
  fclose(f);

  ASSERT_INT_EQ(read_secret_file(path, &cfg), 0);
  ASSERT_TRUE(cfg.secret_len > 0);

  unlink(path);
}

static void test_drop_privs_noop(void)
{
  /* not root — drop_privileges should be a no-op */
  ASSERT_INT_EQ(drop_privileges("nobody", "nogroup", 1), 0);
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

  rate_limit_reset();

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  cfg.test_mode = 1;
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;

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

  rate_limit_reset();
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
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
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

  rate_limit_reset();
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
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
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

  rate_limit_reset();
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
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
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

static void do_fail_auth(struct daemon *d, uint32_t src_ip, uint16_t daemon_port)
{
  int s;

  (void)src_ip;
  g_udp_recv_len = 6;
  memcpy(g_udp_recv_buf, "000000", 6);
  g_udp_recv_src_ip = src_ip;
  g_udp_recv_src_port = 9999;
  g_udp_recv_done = 0;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  sendto(s, "x", 1, 0, (const struct sockaddr *)&(struct sockaddr_in) {
         .sin_family = AF_INET,
         .sin_port = htons(daemon_port),
         .sin_addr.s_addr = htonl(0x7f000001)
         },
         sizeof(struct sockaddr_in));
  close(s);
  ASSERT_INT_EQ(daemon_process(d), 0);
}

static void test_daemon_rate_limit_block(void)
{
  struct config cfg;
  struct daemon d;
  unsigned char test_secret[20];
  int i;

  rate_limit_reset();
  mock_netlink_reset();
  mock_udp_reset();

  for (i = 0; i < 20; i++) {
    test_secret[i] = (unsigned char)(i + 1);
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2225;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
  memcpy(cfg.secret, test_secret, 20);

  ASSERT_INT_EQ(daemon_setup(&d, &cfg), 0);

  /* 5 failed auths from the same IP */
  for (i = 0; i < 5; i++) {
    do_fail_auth(&d, 0x0a0a0a0a, 2225);
  }

  /* after 5 failures, the 6th should be rate limited (blocked) */
  /* the g_udp_recv data doesn't matter — rate_limit_check should reject it */
  g_udp_recv_done = 0;
  {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(s, "x", 1, 0, (const struct sockaddr *)&(struct sockaddr_in) {
           .sin_family = AF_INET,
           .sin_port = htons(2225),
           .sin_addr.s_addr = htonl(0x7f000001)
           },
           sizeof(struct sockaddr_in));
    close(s);
  }
  ASSERT_INT_EQ(daemon_process(&d), 0);

  /* rate limit should have blocked — netlink_insert NOT called */
  ASSERT_INT_EQ((int)g_nl_insert_ip, 0);

  daemon_cleanup(&d);
}

static void test_daemon_rate_limit_success_clears(void)
{
  struct config cfg;
  struct daemon d;
  unsigned char test_secret[20];
  int i;
  uint32_t token;
  uint64_t counter;
  char pkt[32];

  rate_limit_reset();
  mock_netlink_reset();
  mock_udp_reset();

  for (i = 0; i < 20; i++) {
    test_secret[i] = (unsigned char)(i + 1);
  }

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2226;
  cfg.target_port = 22;
  cfg.secret_len = 20;
  cfg.foreground = 1;
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
  memcpy(cfg.secret, test_secret, 20);

  ASSERT_INT_EQ(daemon_setup(&d, &cfg), 0);

  /* 4 failed auths from the same IP */
  for (i = 0; i < 4; i++) {
    do_fail_auth(&d, 0x0b0b0b0b, 2226);
  }

  /* 5th attempt: send a valid TOTP — should succeed and clear rate limit */
  counter = (uint64_t) (time(NULL) / 30);
  token = totp_generate(test_secret, 20, counter, 6);
  pkt[0] = '\0';
  snprintf(pkt, sizeof(pkt), "%06u", (unsigned)token);

  g_udp_recv_len = strlen(pkt);
  memcpy(g_udp_recv_buf, pkt, g_udp_recv_len);
  g_udp_recv_src_ip = 0x0b0b0b0b;
  g_udp_recv_src_port = 9999;
  g_udp_recv_done = 0;

  {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    sendto(s, "x", 1, 0, (const struct sockaddr *)&(struct sockaddr_in) {
           .sin_family = AF_INET,
           .sin_port = htons(2226),
           .sin_addr.s_addr = htonl(0x7f000001)
           },
           sizeof(struct sockaddr_in));
    close(s);
  }
  ASSERT_INT_EQ(daemon_process(&d), 0);

  /* rate limit should be cleared — netlink_insert WAS called */
  ASSERT_INT_EQ((int)g_nl_insert_ip, 0x0b0b0b0b);

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
      TEST(test_daemon_truncated_packet),
      TEST(test_parse_min_block), TEST(test_parse_min_block_bad),
      TEST(test_parse_max_block), TEST(test_parse_rate_limit),
      TEST(test_parse_rate_limit_bad),
      TEST(test_daemon_rate_limit_block),
      TEST(test_daemon_rate_limit_success_clears), TEST(test_prune_expired), TEST(test_prune_fresh_kept),
      TEST(test_parse_user), TEST(test_parse_group),
      TEST(test_parse_secret_file), TEST(test_parse_secret_file_too_long),
      TEST(test_parse_secret_mutual_exclusive), TEST(test_read_secret_file_ok), TEST(test_drop_privs_noop), END_TEST};

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
