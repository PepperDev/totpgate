#include "test_runner.h"
#include "client.h"
#include "encode.h"

#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ---- parse_args tests ---- */

static void test_parse_args_minimal(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP", "127.0.0.1", NULL };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 4, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.port, 2222);
  ASSERT_INT_EQ(cfg.secret_len, 10);
  ASSERT_STREQ(cfg.server, "127.0.0.1");
  ASSERT_INT_EQ(cfg.have_target_port, 0);
}

static void test_parse_args_all_options(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    "--port", "8080", "example.com", "443", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 7, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)cfg.port, 8080);
  ASSERT_INT_EQ(cfg.secret_len, 10);
  ASSERT_STREQ(cfg.server, "example.com");
  ASSERT_INT_EQ(cfg.have_target_port, 1);
  ASSERT_INT_EQ((int)cfg.target_port, 443);
}

static void test_parse_args_missing_secret(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "127.0.0.1", NULL };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 2, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_missing_server(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP", NULL };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 3, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_bad_port(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    "--port", "0", "127.0.0.1", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_bad_port_overflow(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    "--port", "65536", "127.0.0.1", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_bad_target_port(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    "127.0.0.1", "0", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_bad_target_port_overflow(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    "127.0.0.1", "65536", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_invalid_secret(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "!!!invalid!!!",
    "127.0.0.1", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 4, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_unknown_option(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    "--bogus", "127.0.0.1", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 5, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_server_too_long(void)
{
  struct client_cfg cfg;
  char long_name[300];
  char *argv[] = { "totpgate", "--secret", "JBSWY3DPEHPK3PXP",
    long_name, NULL
  };
  int ret;

  memset(long_name, 'x', sizeof(long_name) - 1);
  long_name[sizeof(long_name) - 1] = '\0';
  optind = 0;
  ret = parse_args(&cfg, 4, argv);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_args_hex_secret(void)
{
  struct client_cfg cfg;
  char *argv[] = { "totpgate", "--secret", "hex:48656c6c6f",
    "127.0.0.1", NULL
  };
  int ret;

  optind = 0;
  ret = parse_args(&cfg, 4, argv);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ(cfg.secret_len, 5);
}

/* ---- client_run tests ---- */

static void test_client_run_success(void)
{
  struct client_cfg cfg;
  struct sockaddr_in bind_addr;
  socklen_t addrlen;
  int listener;
  unsigned char secret[20];
  size_t slen;
  enum secret_encoding enc;
  char buf[64];
  ssize_t n;
  int ret;

  /* set up a UDP listener */
  listener = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(listener >= 0);

  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind_addr.sin_port = 0;
  ret = bind(listener, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
  ASSERT_INT_EQ(ret, 0);

  addrlen = sizeof(bind_addr);
  ret = getsockname(listener, (struct sockaddr *)&bind_addr, &addrlen);
  ASSERT_INT_EQ(ret, 0);

  slen = sizeof(secret);
  ret = secret_decode("JBSWY3DPEHPK3PXP", secret, &slen, &enc);
  ASSERT_INT_EQ(ret, 0);

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = ntohs(bind_addr.sin_port);
  cfg.secret_len = slen;
  memcpy(cfg.secret, secret, slen);
  snprintf(cfg.server, sizeof(cfg.server), "127.0.0.1");

  ret = client_run(&cfg);
  ASSERT_INT_EQ(ret, 0);

  n = recv(listener, buf, sizeof(buf), 0);
  ASSERT_TRUE(n >= 6);
  ASSERT_TRUE(buf[5] == ':' || (buf[5] >= '0' && buf[5] <= '9'));

  close(listener);
}

static void test_client_run_with_target_port(void)
{
  struct client_cfg cfg;
  struct sockaddr_in bind_addr;
  socklen_t addrlen;
  int listener;
  unsigned char secret[20];
  size_t slen;
  enum secret_encoding enc;
  char buf[64];
  ssize_t n;
  int ret;

  listener = socket(AF_INET, SOCK_DGRAM, 0);
  ASSERT_TRUE(listener >= 0);

  memset(&bind_addr, 0, sizeof(bind_addr));
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind_addr.sin_port = 0;
  ret = bind(listener, (const struct sockaddr *)&bind_addr, sizeof(bind_addr));
  ASSERT_INT_EQ(ret, 0);

  addrlen = sizeof(bind_addr);
  ret = getsockname(listener, (struct sockaddr *)&bind_addr, &addrlen);
  ASSERT_INT_EQ(ret, 0);

  slen = sizeof(secret);
  ret = secret_decode("JBSWY3DPEHPK3PXP", secret, &slen, &enc);
  ASSERT_INT_EQ(ret, 0);

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = ntohs(bind_addr.sin_port);
  cfg.secret_len = slen;
  memcpy(cfg.secret, secret, slen);
  snprintf(cfg.server, sizeof(cfg.server), "127.0.0.1");
  cfg.target_port = 8080;
  cfg.have_target_port = 1;

  ret = client_run(&cfg);
  ASSERT_INT_EQ(ret, 0);

  n = recv(listener, buf, sizeof(buf), 0);
  ASSERT_TRUE(n >= 6);
  buf[n] = '\0';
  ASSERT_TRUE(strstr(buf, ":8080") != NULL);

  close(listener);
}

static void test_client_run_resolve_fail(void)
{
  struct client_cfg cfg;
  int ret;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.secret_len = 10;
  memset(cfg.secret, 0, 10);
  snprintf(cfg.server, sizeof(cfg.server), "nonexistent-host-that-definitely-does-not-exist.example.invalid");

  ret = client_run(&cfg);
  ASSERT_INT_EQ(ret, -1);
}

TEST_GROUP(client)
{
TEST(test_parse_args_minimal),
      TEST(test_parse_args_all_options),
      TEST(test_parse_args_missing_secret),
      TEST(test_parse_args_missing_server),
      TEST(test_parse_args_bad_port),
      TEST(test_parse_args_bad_port_overflow),
      TEST(test_parse_args_bad_target_port),
      TEST(test_parse_args_bad_target_port_overflow),
      TEST(test_parse_args_invalid_secret),
      TEST(test_parse_args_unknown_option),
      TEST(test_parse_args_server_too_long),
      TEST(test_parse_args_hex_secret),
      TEST(test_client_run_success),
      TEST(test_client_run_with_target_port), TEST(test_client_run_resolve_fail), END_TEST};

#ifdef BUILD_CLIENT_TEST_MAIN
int main(void)
{
  int passed = 0;
  int failed = 0;
  int ti;

  printf("client:\n");
  for (ti = 0; client_tests[ti].fn != NULL; ti++) {
    printf("  %s ... ", client_tests[ti].name);
    client_tests[ti].fn();
    printf("OK\n");
    passed++;
  }

  printf("\n%d passed, %d failed\n", passed, failed);
  return failed;
}
#endif
