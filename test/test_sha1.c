#include "test_runner.h"
#include "sha1.h"

static void hex_to_bytes(const char *hex, unsigned char *out, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++) {
        unsigned int byte;
        sscanf(hex + i * 2, "%2x", &byte);
        out[i] = (unsigned char)byte;
    }
}

static int memcmp_digest(const unsigned char *a, const unsigned char *b)
{
    size_t i;
    for (i = 0; i < SHA1_DIGEST_LEN; i++) {
        if (a[i] != b[i])
            return (int)a[i] - (int)b[i];
    }
    return 0;
}

static void test_empty(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    hex_to_bytes("da39a3ee5e6b4b0d3255bfef95601890afd80709", expected, SHA1_DIGEST_LEN);
    sha1((const unsigned char *)"", 0, out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_abc(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    hex_to_bytes("a9993e364706816aba3e25717850c26c9cd0d89d", expected, SHA1_DIGEST_LEN);
    sha1((const unsigned char *)"abc", 3, out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_long(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    hex_to_bytes("84983e441c3bd26ebaae4aa1f95129e5e54670f1", expected, SHA1_DIGEST_LEN);
    sha1((const unsigned char *)msg, strlen(msg), out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_single_byte(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    hex_to_bytes("86f7e437faa5a7fce15d1ddcb9eaeaea377667b8", expected, SHA1_DIGEST_LEN);
    sha1((const unsigned char *)"a", 1, out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_55_bytes(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    unsigned char msg[55];
    size_t i;
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)('a' + (i % 26));
    hex_to_bytes("a617d006d1ca12671785098a19a87fe58443bde9", expected, SHA1_DIGEST_LEN);
    sha1(msg, sizeof(msg), out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_56_bytes(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    unsigned char msg[56];
    size_t i;
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)('a' + (i % 26));
    hex_to_bytes("4ad5bb7ae3c4024768d364b77c52128ea3cffebe", expected, SHA1_DIGEST_LEN);
    sha1(msg, sizeof(msg), out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_64_bytes(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    unsigned char msg[64];
    size_t i;
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)('a' + (i % 26));
    hex_to_bytes("93249d4c2f8903ebf41ac358473148ae6ddd7042", expected, SHA1_DIGEST_LEN);
    sha1(msg, sizeof(msg), out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_65_bytes(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    unsigned char msg[65];
    size_t i;
    for (i = 0; i < sizeof(msg); i++)
        msg[i] = (unsigned char)('a' + (i % 26));
    hex_to_bytes("cf2a63cc308225cf07b498d2309a01dd0df52f67", expected, SHA1_DIGEST_LEN);
    sha1(msg, sizeof(msg), out);
    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

static void test_one_million_a(void)
{
    unsigned char out[SHA1_DIGEST_LEN];
    unsigned char expected[SHA1_DIGEST_LEN];
    sha1_ctx_t ctx;
    unsigned char block[1000];
    int i;

    hex_to_bytes("34aa973cd4c4daa4f61eeb2bdbad27316534016f", expected, SHA1_DIGEST_LEN);

    memset(block, 'a', sizeof(block));

    sha1_init(&ctx);
    for (i = 0; i < 1000; i++)
        sha1_update(&ctx, block, sizeof(block));
    sha1_final(&ctx, out);

    ASSERT_TRUE(memcmp_digest(out, expected) == 0);
}

TEST_GROUP(sha1) {
    TEST(test_empty),
    TEST(test_abc),
    TEST(test_long),
    TEST(test_single_byte),
    TEST(test_55_bytes),
    TEST(test_56_bytes),
    TEST(test_64_bytes),
    TEST(test_65_bytes),
    TEST(test_one_million_a),
    END_TEST
};
