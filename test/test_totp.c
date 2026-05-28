#include "test_runner.h"
#include "totp.h"

#include <string.h>

static const unsigned char g_secret[20] = {
  0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
  0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
  0x37, 0x38, 0x39, 0x30,
};

static void test_rfc6238_vector(uint64_t time_sec, int step, int digits, uint32_t expected)
{
  uint64_t counter = time_sec / (uint64_t) step;
  uint32_t token = totp_generate(g_secret, sizeof(g_secret),
                                 counter, digits);
  ASSERT_INT_EQ((int)token, (int)expected);
}

static void test_t59(void)
{
  test_rfc6238_vector(59, 30, 8, 94287082);
}

static void test_t1111111109(void)
{
  test_rfc6238_vector(1111111109, 30, 8, 7081804);
}

static void test_t1111111111(void)
{
  test_rfc6238_vector(1111111111, 30, 8, 14050471);
}

static void test_t1234567890(void)
{
  test_rfc6238_vector(1234567890, 30, 8, 89005924);
}

static void test_t2000000000(void)
{
  test_rfc6238_vector(2000000000, 30, 8, 69279037);
}

static void test_t20000000000(void)
{
  test_rfc6238_vector(20000000000ULL, 30, 8, 65353130);
}

static void test_6_digits(void)
{
  test_rfc6238_vector(59, 30, 6, 287082);
}

static void test_7_digits(void)
{
  test_rfc6238_vector(59, 30, 7, 4287082);
}

/* Validate with no drift: should pass at exact time */
static void test_validate_exact(void)
{
  int ret = totp_validate(g_secret, sizeof(g_secret),
                          94287082, 8, 30, 0, 0, 59, NULL);
  ASSERT_INT_EQ(ret, 0);
}

static void test_validate_drift_ahead(void)
{
  int ret = totp_validate(g_secret, sizeof(g_secret),
                          14050471, 8, 30, 0, 1, 1111111081, NULL);
  ASSERT_INT_EQ(ret, 0);
}

static void test_validate_drift_behind(void)
{
  int ret = totp_validate(g_secret, sizeof(g_secret),
                          94287082, 8, 30, 1, 0, 89, NULL);
  ASSERT_INT_EQ(ret, 0);
}

static void test_validate_wrong(void)
{
  int ret = totp_validate(g_secret, sizeof(g_secret),
                          12345678, 8, 30, 0, 0, 59, NULL);
  ASSERT_INT_EQ(ret, -1);
}

static void test_validate_counter(void)
{
  uint64_t counter = 0;
  int ret = totp_validate(g_secret, sizeof(g_secret),
                          94287082, 8, 30, 0, 0, 59, &counter);
  ASSERT_INT_EQ(ret, 0);
  ASSERT_INT_EQ((int)counter, 1);
}

static void test_validate_counter_drift(void)
{
  uint64_t counter = 0;
  int ret = totp_validate(g_secret, sizeof(g_secret),
                          14050471, 8, 30, 0, 1, 1111111081,
                          &counter);
  ASSERT_INT_EQ(ret, 0);
  /* time 1111111081 → current = 1111111081/30 = 37037036,
     matching token is at d=+1 → counter = 37037037 */
  ASSERT_INT_EQ((int)counter, 37037037);
}

TEST_GROUP(totp)
{
TEST(test_t59),
      TEST(test_t1111111109),
      TEST(test_t1111111111),
      TEST(test_t1234567890),
      TEST(test_t2000000000),
      TEST(test_t20000000000),
      TEST(test_6_digits),
      TEST(test_7_digits),
      TEST(test_validate_exact),
      TEST(test_validate_drift_ahead),
      TEST(test_validate_drift_behind),
      TEST(test_validate_wrong), TEST(test_validate_counter), TEST(test_validate_counter_drift), END_TEST};
