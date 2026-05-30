#include "test_runner.h"
#include "auth.h"
#include "addr.h"

#include <string.h>

static const unsigned char g_secret[20] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30,
};

/* helper to build an ip_addr_t from a uint32 IPv4 address */
static ip_addr_t ip4(uint32_t v4)
{
  ip_addr_t ip;

  ip.family = AF_INET;
  memcpy(ip.addr, &v4, 4);
  memset(ip.addr + 4, 0, 12);
  return ip;
}

/* ---- auth_parse tests ---- */

static void test_parse_token_only(void)
{
  const unsigned char data[] = "287082";
  uint32_t token = 0;
  int ret = auth_parse(data, sizeof(data) - 1, &token);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)token, 287082);
}

static void test_parse_8_digit_token(void)
{
  const unsigned char data[] = "94287082";
  uint32_t token = 0;
  int ret = auth_parse(data, sizeof(data) - 1, &token);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)token, 94287082);
}

static void test_parse_empty(void)
{
  const unsigned char data[] = "";
  int ret = auth_parse(data, 0, NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_null(void)
{
  int ret = auth_parse(NULL, 5, NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_too_long(void)
{
  unsigned char data[260];
  int ret;

  memset(data, '0', sizeof(data));
  ret = auth_parse(data, sizeof(data), NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_short_token(void)
{
  const unsigned char data[] = "12345";
  int ret = auth_parse(data, sizeof(data) - 1, NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_long_token(void)
{
  const unsigned char data[] = "123456789";
  int ret = auth_parse(data, sizeof(data) - 1, NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_non_digit_token(void)
{
  const unsigned char data[] = "abcdef";
  int ret = auth_parse(data, sizeof(data) - 1, NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_parse_trailing_rejected(void)
{
  const unsigned char data[] = "287082:80";
  int ret = auth_parse(data, sizeof(data) - 1, NULL);
  ASSERT_INT_EQ(ret, -1);
}

/* ---- auth_validate tests ---- */

static void test_validate_exact(void)
{
  const struct totp_params p = {
    .src_ip = ip4(0x01010101),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  auth_replay_reset();
  int ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p);
  ASSERT_INT_EQ(ret, 0);
}

static void test_validate_drift_ahead(void)
{
  const struct totp_params p = {
    .src_ip = ip4(0x01010101),.now = 1111111081,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 1,
  };
  auth_replay_reset();
  int ret = auth_validate(g_secret, sizeof(g_secret), 14050471, &p);
  ASSERT_INT_EQ(ret, 0);
}

static void test_validate_drift_behind(void)
{
  const struct totp_params p = {
    .src_ip = ip4(0x01010101),.now = 89,.digits = 8,.step = 30,
    .drift_behind = 1,.drift_ahead = 0,
  };
  auth_replay_reset();
  int ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p);
  ASSERT_INT_EQ(ret, 0);
}

static void test_validate_wrong_token(void)
{
  const struct totp_params p = {
    .src_ip = ip4(0x01010101),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  auth_replay_reset();
  int ret = auth_validate(g_secret, sizeof(g_secret), 12345678, &p);
  ASSERT_INT_EQ(ret, -1);
}

/* ---- replay tests ---- */

static void test_replay_same_window(void)
{
  const struct totp_params p = {
    .src_ip = ip4(0x02020202),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  auth_replay_reset();

  int ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p);
  ASSERT_INT_EQ(ret, 0);

  ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p);
  ASSERT_INT_EQ(ret, -1);
}

static void test_replay_different_ip(void)
{
  const struct totp_params p1 = {
    .src_ip = ip4(0x03030303),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  const struct totp_params p2 = {
    .src_ip = ip4(0x04040404),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  auth_replay_reset();

  int ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p1);
  ASSERT_INT_EQ(ret, 0);

  ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p2);
  ASSERT_INT_EQ(ret, 0);
}

static void test_replay_older_seq(void)
{
  const struct totp_params p59 = {
    .src_ip = ip4(0x05050505),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  const struct totp_params p29 = {
    .src_ip = ip4(0x05050505),.now = 29,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 0,
  };
  auth_replay_reset();

  int ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p59);
  ASSERT_INT_EQ(ret, 0);

  /* t=29 is in the same window as t=59 (counter=1 for both with 30s step) */
  ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p29);
  ASSERT_INT_EQ(ret, -1);
}

static void test_replay_newer_seq_ok(void)
{
  const struct totp_params p59 = {
    .src_ip = ip4(0x06060606),.now = 59,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 1,
  };
  const struct totp_params p1081 = {
    .src_ip = ip4(0x06060606),.now = 1111111081,.digits = 8,.step = 30,
    .drift_behind = 0,.drift_ahead = 1,
  };
  auth_replay_reset();

  /* t=59 -> counter=1 */
  int ret = auth_validate(g_secret, sizeof(g_secret), 94287082, &p59);
  ASSERT_INT_EQ(ret, 0);

  /* t=1111111081 -> counter=37037036, with drift_ahead=1 matches counter=37037037 */
  ret = auth_validate(g_secret, sizeof(g_secret), 14050471, &p1081);
  ASSERT_INT_EQ(ret, 0);
}

/* ---- auth_seen_before / auth_record_seq tests ---- */

static void test_seen_not_recorded(void)
{
  ip_addr_t ip = ip4(0x07070707);

  auth_replay_reset();
  int ret = auth_seen_before(42, &ip);
  ASSERT_INT_EQ(ret, 0);
}

static void test_record_and_check(void)
{
  ip_addr_t ip = ip4(0x08080808);

  auth_replay_reset();
  int ret = auth_record_seq(42, &ip);
  ASSERT_INT_EQ(ret, 0);

  ret = auth_seen_before(42, &ip);
  ASSERT_INT_EQ(ret, -1);

  ret = auth_seen_before(41, &ip);
  ASSERT_INT_EQ(ret, -1);

  ret = auth_seen_before(43, &ip);
  ASSERT_INT_EQ(ret, 0);
}

TEST_GROUP(auth)
{
TEST(test_parse_token_only),
      TEST(test_parse_8_digit_token),
      TEST(test_parse_empty),
      TEST(test_parse_null),
      TEST(test_parse_too_long),
      TEST(test_parse_short_token),
      TEST(test_parse_long_token),
      TEST(test_parse_non_digit_token),
      TEST(test_parse_trailing_rejected),
      TEST(test_validate_exact),
      TEST(test_validate_drift_ahead),
      TEST(test_validate_drift_behind),
      TEST(test_validate_wrong_token),
      TEST(test_replay_same_window),
      TEST(test_replay_different_ip),
      TEST(test_replay_older_seq),
      TEST(test_replay_newer_seq_ok), TEST(test_seen_not_recorded), TEST(test_record_and_check), END_TEST};
