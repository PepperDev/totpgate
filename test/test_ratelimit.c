#include "test_runner.h"
#include "ratelimit.h"

#include <string.h>

static const struct rate_limit_cfg g_cfg = { 300, 86400, 5, 60 };

/* ---- rate_limit_check tests ---- */

static void test_check_not_blocked_empty(void)
{
  rate_limit_reset();
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1000), 0);
}

static void test_check_blocked(void)
{
  rate_limit_reset();
  /* simulate 5 failures */
  rate_limit_fail(0x01010101, 1000, &g_cfg);
  rate_limit_fail(0x01010101, 1010, &g_cfg);
  rate_limit_fail(0x01010101, 1020, &g_cfg);
  rate_limit_fail(0x01010101, 1030, &g_cfg);
  rate_limit_fail(0x01010101, 1040, &g_cfg);

  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), -1);
}

static void test_check_not_blocked_after_expiry(void)
{
  rate_limit_reset();
  int i;

  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }

  /* last fail at 1040 → block_until = 1040 + 300 = 1340 */
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1339), -1);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1341), 0);
}

static void test_check_different_ip_not_blocked(void)
{
  rate_limit_reset();
  int i;

  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }

  ASSERT_INT_EQ(rate_limit_check(0x02020202, 1040), 0);
}

/* ---- rate_limit_fail tests ---- */

static void test_fail_first_block_basic(void)
{
  rate_limit_reset();
  int i;

  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }

  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), -1);
}

static void test_fail_window_reset(void)
{
  rate_limit_reset();

  /* 5 failures within window → blocked */
  rate_limit_fail(0x01010101, 1000, &g_cfg);
  rate_limit_fail(0x01010101, 1010, &g_cfg);
  rate_limit_fail(0x01010101, 1020, &g_cfg);
  rate_limit_fail(0x01010101, 1030, &g_cfg);
  rate_limit_fail(0x01010101, 1040, &g_cfg);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), -1);

  /* after block expires, fail again — window has expired (1000 → 2000) */
  /* block_until = 1300, so at 2000 we're past it */
  rate_limit_fail(0x01010101, 2000, &g_cfg);
  /* window check: 2000 - first_fail(1000) = 1000 > 60 → window reset */
  /* fail_count = 1, no block yet */
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 2000), 0);
}

static void test_fail_exponential_backoff(void)
{
  rate_limit_reset();

  /* first block: 5 fails, min_block = 300 */
  rate_limit_fail(0x01010101, 1000, &g_cfg);
  rate_limit_fail(0x01010101, 1010, &g_cfg);
  rate_limit_fail(0x01010101, 1020, &g_cfg);
  rate_limit_fail(0x01010101, 1030, &g_cfg);
  rate_limit_fail(0x01010101, 1040, &g_cfg);
  /* block_until = 1040 + 300 = 1340 */
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1339), -1);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1341), 0);

  /* second block: block_duration should be 600 */
  rate_limit_fail(0x01010101, 1341, &g_cfg);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1341), 0); /* only 1 fail */
  rate_limit_fail(0x01010101, 1351, &g_cfg);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1351), 0);
  rate_limit_fail(0x01010101, 1361, &g_cfg);
  rate_limit_fail(0x01010101, 1371, &g_cfg);
  rate_limit_fail(0x01010101, 1381, &g_cfg);
  /* block_until = 1381 + 600 = 1981 */
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1980), -1);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1982), 0);
}

static void test_fail_multiple_ips(void)
{
  rate_limit_reset();
  int i;

  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }
  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x02020202, (time_t) (1000 + i * 10), &g_cfg);
  }

  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), -1);
  ASSERT_INT_EQ(rate_limit_check(0x02020202, 1040), -1);
  ASSERT_INT_EQ(rate_limit_check(0x03030303, 1040), 0);
}

static void test_fail_below_threshold(void)
{
  rate_limit_reset();
  int i;

  for (i = 0; i < 4; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }

  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), 0);
}

/* ---- rate_limit_success tests ---- */

static void test_success_clears_block(void)
{
  rate_limit_reset();
  int i;

  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }

  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), -1);

  rate_limit_success(0x01010101);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), 0);
}

static void test_success_unknown_ip(void)
{
  rate_limit_reset();
  /* no entry exists, should not crash */
  rate_limit_success(0x01010101);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1000), 0);
}

static void test_success_resets_fail_count(void)
{
  rate_limit_reset();

  rate_limit_fail(0x01010101, 1000, &g_cfg);
  rate_limit_fail(0x01010101, 1010, &g_cfg);
  rate_limit_fail(0x01010101, 1020, &g_cfg);

  rate_limit_success(0x01010101);

  /* after success, subsequent failures should start fresh */
  rate_limit_fail(0x01010101, 1030, &g_cfg);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1030), 0);
  rate_limit_fail(0x01010101, 1040, &g_cfg);
  rate_limit_fail(0x01010101, 1050, &g_cfg);
  rate_limit_fail(0x01010101, 1060, &g_cfg);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1060), 0); /* only 4 fails so far */
}

/* ---- mix: fail + success cycles ---- */

static void test_fail_success_cycle(void)
{
  rate_limit_reset();
  int i;

  /* first batch: 5 fails → blocked */
  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1000 + i * 10), &g_cfg);
  }
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1040), -1);

  /* success clears */
  rate_limit_success(0x01010101);
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1050), 0);

  /* second batch: 5 more fails should use a fresh block duration */
  for (i = 0; i < 5; i++) {
    rate_limit_fail(0x01010101, (time_t) (1050 + i * 10), &g_cfg);
  }
  ASSERT_INT_EQ(rate_limit_check(0x01010101, 1100), -1);
}

TEST_GROUP(ratelimit)
{
TEST(test_check_not_blocked_empty),
      TEST(test_check_blocked),
      TEST(test_check_not_blocked_after_expiry),
      TEST(test_check_different_ip_not_blocked),
      TEST(test_fail_first_block_basic),
      TEST(test_fail_window_reset),
      TEST(test_fail_exponential_backoff),
      TEST(test_fail_multiple_ips),
      TEST(test_fail_below_threshold),
      TEST(test_success_clears_block),
      TEST(test_success_unknown_ip), TEST(test_success_resets_fail_count), TEST(test_fail_success_cycle), END_TEST};
