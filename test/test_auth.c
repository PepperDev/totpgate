#include "test_runner.h"
#include "auth.h"

#include <string.h>

static const unsigned char g_secret[20] = {
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x30,
};

/* ---- auth_parse tests ---- */

static void test_parse_token_only(void)
{
    const unsigned char data[] = "287082";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)token, 287082);
    ASSERT_INT_EQ((int)port, 0);
    ASSERT_INT_EQ((int)lifetime, 0);
}

static void test_parse_token_port(void)
{
    const unsigned char data[] = "482639:443";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)token, 482639);
    ASSERT_INT_EQ((int)port, 443);
    ASSERT_INT_EQ((int)lifetime, 0);
}

static void test_parse_token_port_lifetime(void)
{
    const unsigned char data[] = "482639:443:120";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)token, 482639);
    ASSERT_INT_EQ((int)port, 443);
    ASSERT_INT_EQ((int)lifetime, 120);
}

static void test_parse_zero_port(void)
{
    const unsigned char data[] = "482639:0";
    uint32_t token = 0;
    uint16_t port = 9999;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)port, 0);
}

static void test_parse_zero_lifetime(void)
{
    const unsigned char data[] = "482639:443:0";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 9999;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)lifetime, 0);
}

static void test_parse_trailing_ignored(void)
{
    const unsigned char data[] = "287082:80:30extra";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)token, 287082);
    ASSERT_INT_EQ((int)port, 80);
    ASSERT_INT_EQ((int)lifetime, 30);
}

static void test_parse_8_digit_token(void)
{
    const unsigned char data[] = "94287082";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)token, 94287082);
}

static void test_parse_empty(void)
{
    const unsigned char data[] = "";
    int ret = auth_parse(data, 0, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_null(void)
{
    int ret = auth_parse(NULL, 5, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_too_long(void)
{
    unsigned char data[260];
    int ret;

    memset(data, '0', sizeof(data));
    ret = auth_parse(data, sizeof(data), NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_short_token(void)
{
    const unsigned char data[] = "12345";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_long_token(void)
{
    const unsigned char data[] = "123456789";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_non_digit_token(void)
{
    const unsigned char data[] = "abcdef";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_bad_port(void)
{
    const unsigned char data[] = "287082:abc";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_port_overflow(void)
{
    const unsigned char data[] = "287082:65536";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_bad_lifetime(void)
{
    const unsigned char data[] = "287082:80:xyz";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_lifetime_overflow(void)
{
    const unsigned char data[] = "287082:80:86401";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, -1);
}

static void test_parse_port_max(void)
{
    const unsigned char data[] = "287082:65535";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)port, 65535);
}

static void test_parse_lifetime_max(void)
{
    const unsigned char data[] = "287082:80:86400";
    uint32_t token = 0;
    uint16_t port = 0;
    uint32_t lifetime = 0;
    int ret = auth_parse(data, sizeof(data) - 1,
                         &token, &port, &lifetime);
    ASSERT_INT_EQ(ret, 0);
    ASSERT_INT_EQ((int)lifetime, 86400);
}

static void test_parse_null_output_ptrs(void)
{
    const unsigned char data[] = "287082:443:120";
    int ret = auth_parse(data, sizeof(data) - 1, NULL, NULL, NULL);
    ASSERT_INT_EQ(ret, 0);
}

/* ---- auth_validate tests ---- */

static void test_validate_exact(void)
{
    auth_replay_reset();
    int ret = auth_validate(g_secret, sizeof(g_secret),
                            94287082, 0x01010101, 59,
                            8, 30, 0, 0);
    ASSERT_INT_EQ(ret, 0);
}

static void test_validate_drift_ahead(void)
{
    auth_replay_reset();
    int ret = auth_validate(g_secret, sizeof(g_secret),
                            14050471, 0x01010101, 1111111081,
                            8, 30, 0, 1);
    ASSERT_INT_EQ(ret, 0);
}

static void test_validate_drift_behind(void)
{
    auth_replay_reset();
    int ret = auth_validate(g_secret, sizeof(g_secret),
                            94287082, 0x01010101, 89,
                            8, 30, 1, 0);
    ASSERT_INT_EQ(ret, 0);
}

static void test_validate_wrong_token(void)
{
    auth_replay_reset();
    int ret = auth_validate(g_secret, sizeof(g_secret),
                            12345678, 0x01010101, 59,
                            8, 30, 0, 0);
    ASSERT_INT_EQ(ret, -1);
}

/* ---- replay tests ---- */

static void test_replay_same_window(void)
{
    auth_replay_reset();

    int ret = auth_validate(g_secret, sizeof(g_secret),
                            94287082, 0x02020202, 59,
                            8, 30, 0, 0);
    ASSERT_INT_EQ(ret, 0);

    ret = auth_validate(g_secret, sizeof(g_secret),
                        94287082, 0x02020202, 59,
                        8, 30, 0, 0);
    ASSERT_INT_EQ(ret, -1);
}

static void test_replay_different_ip(void)
{
    auth_replay_reset();

    int ret = auth_validate(g_secret, sizeof(g_secret),
                            94287082, 0x03030303, 59,
                            8, 30, 0, 0);
    ASSERT_INT_EQ(ret, 0);

    ret = auth_validate(g_secret, sizeof(g_secret),
                        94287082, 0x04040404, 59,
                        8, 30, 0, 0);
    ASSERT_INT_EQ(ret, 0);
}

static void test_replay_older_seq(void)
{
    auth_replay_reset();

    int ret = auth_validate(g_secret, sizeof(g_secret),
                            94287082, 0x05050505, 59,
                            8, 30, 0, 0);
    ASSERT_INT_EQ(ret, 0);

    /* t=29 is in the same window as t=59 (counter=1 for both with 30s step) */
    ret = auth_validate(g_secret, sizeof(g_secret),
                        94287082, 0x05050505, 29,
                        8, 30, 0, 0);
    ASSERT_INT_EQ(ret, -1);
}

static void test_replay_newer_seq_ok(void)
{
    auth_replay_reset();

    /* t=59 → counter=1 */
    int ret = auth_validate(g_secret, sizeof(g_secret),
                            94287082, 0x06060606, 59,
                            8, 30, 0, 1);
    ASSERT_INT_EQ(ret, 0);

    /* t=1111111081 → counter=37037036, with drift_ahead=1 matches counter=37037037 */
    ret = auth_validate(g_secret, sizeof(g_secret),
                        14050471, 0x06060606, 1111111081,
                        8, 30, 0, 1);
    ASSERT_INT_EQ(ret, 0);
}

/* ---- auth_seen_before / auth_record_seq tests ---- */

static void test_seen_not_recorded(void)
{
    auth_replay_reset();
    int ret = auth_seen_before(42, 0x07070707);
    ASSERT_INT_EQ(ret, 0);
}

static void test_record_and_check(void)
{
    auth_replay_reset();
    int ret = auth_record_seq(42, 0x08080808);
    ASSERT_INT_EQ(ret, 0);

    ret = auth_seen_before(42, 0x08080808);
    ASSERT_INT_EQ(ret, -1);

    ret = auth_seen_before(41, 0x08080808);
    ASSERT_INT_EQ(ret, -1);

    ret = auth_seen_before(43, 0x08080808);
    ASSERT_INT_EQ(ret, 0);
}

TEST_GROUP(auth) {
    TEST(test_parse_token_only),
    TEST(test_parse_token_port),
    TEST(test_parse_token_port_lifetime),
    TEST(test_parse_zero_port),
    TEST(test_parse_zero_lifetime),
    TEST(test_parse_trailing_ignored),
    TEST(test_parse_8_digit_token),
    TEST(test_parse_empty),
    TEST(test_parse_null),
    TEST(test_parse_too_long),
    TEST(test_parse_short_token),
    TEST(test_parse_long_token),
    TEST(test_parse_non_digit_token),
    TEST(test_parse_bad_port),
    TEST(test_parse_port_overflow),
    TEST(test_parse_bad_lifetime),
    TEST(test_parse_lifetime_overflow),
    TEST(test_parse_port_max),
    TEST(test_parse_lifetime_max),
    TEST(test_parse_null_output_ptrs),
    TEST(test_validate_exact),
    TEST(test_validate_drift_ahead),
    TEST(test_validate_drift_behind),
    TEST(test_validate_wrong_token),
    TEST(test_replay_same_window),
    TEST(test_replay_different_ip),
    TEST(test_replay_older_seq),
    TEST(test_replay_newer_seq_ok),
    TEST(test_seen_not_recorded),
    TEST(test_record_and_check),
    END_TEST
};
