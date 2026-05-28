#include "test_runner.h"
#include "hmac.h"

#include <string.h>

static void hex_to_bytes(const char *hex, unsigned char *out, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++) {
    unsigned int byte;
    sscanf(hex + i * 2, "%2x", &byte);
    out[i] = (unsigned char)byte;
  }
}

static void fill_byte(unsigned char *buf, size_t len, unsigned char val)
{
  size_t i;
  for (i = 0; i < len; i++)
    buf[i] = val;
}

static void fill_seq(unsigned char *buf, size_t len)
{
  size_t i;
  for (i = 0; i < len; i++)
    buf[i] = (unsigned char)(i + 1);
}

static int check(const unsigned char *got, const unsigned char *expected)
{
  size_t i;
  for (i = 0; i < HMAC_SHA1_LEN; i++) {
    if (got[i] != expected[i])
      return -1;
  }
  return 0;
}

/* RFC 2202 Test Case 1: key=0x0b*20, data="Hi There" */
static void test_rfc2202_1(void)
{
  unsigned char key[20];
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];
  const unsigned char *data = (const unsigned char *)"Hi There";

  fill_byte(key, sizeof(key), 0x0b);
  hex_to_bytes("b617318655057264e28bc0b6fb378c8ef146be00", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, sizeof(key), data, 8, out);
  ASSERT_TRUE(check(out, expected) == 0);
}

/* RFC 2202 Test Case 2: key="Jefe", data="what do ya want for nothing?" */
static void test_rfc2202_2(void)
{
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];
  const unsigned char *key = (const unsigned char *)"Jefe";
  const unsigned char *data = (const unsigned char *)"what do ya want for nothing?";

  hex_to_bytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, 4, data, 28, out);
  ASSERT_TRUE(check(out, expected) == 0);
}

/* RFC 2202 Test Case 3: key=0xaa*20, data=0xdd*50 */
static void test_rfc2202_3(void)
{
  unsigned char key[20];
  unsigned char data[50];
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];

  fill_byte(key, sizeof(key), 0xaa);
  fill_byte(data, sizeof(data), 0xdd);
  hex_to_bytes("125d7342b9ac11cd91a39af48aa17b4f63f175d3", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, sizeof(key), data, sizeof(data), out);
  ASSERT_TRUE(check(out, expected) == 0);
}

/* RFC 2202 Test Case 4: key=0x01..0x19, data=0xcd*50 */
static void test_rfc2202_4(void)
{
  unsigned char key[25];
  unsigned char data[50];
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];

  fill_seq(key, sizeof(key));
  fill_byte(data, sizeof(data), 0xcd);
  hex_to_bytes("4c9007f4026250c6bc8414f9bf50c86c2d7235da", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, sizeof(key), data, sizeof(data), out);
  ASSERT_TRUE(check(out, expected) == 0);
}

/* RFC 2202 Test Case 5: key=0x0c*20, data="Test With Truncation" */
static void test_rfc2202_5(void)
{
  unsigned char key[20];
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];
  const unsigned char *data = (const unsigned char *)"Test With Truncation";

  fill_byte(key, sizeof(key), 0x0c);
  hex_to_bytes("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, sizeof(key), data, 20, out);
  ASSERT_TRUE(check(out, expected) == 0);
}

/* RFC 2202 Test Case 6: key=0xaa*80 (>64), data="Test Using Larger Than Block-Size Key - Hash Key First" */
static void test_rfc2202_6(void)
{
  unsigned char key[80];
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];
  const unsigned char *data = (const unsigned char *)"Test Using Larger Than Block-Size Key - Hash Key First";

  fill_byte(key, sizeof(key), 0xaa);
  hex_to_bytes("aa4ae5e15272d00e95705637ce8a3b55ed402112", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, sizeof(key), data, 54, out);
  ASSERT_TRUE(check(out, expected) == 0);
}

/* RFC 2202 Test Case 7: key=0xaa*80, data="Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data" */
static void test_rfc2202_7(void)
{
  unsigned char key[80];
  unsigned char out[HMAC_SHA1_LEN];
  unsigned char expected[HMAC_SHA1_LEN];
  const unsigned char *data =
      (const unsigned char *)"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";

  fill_byte(key, sizeof(key), 0xaa);
  hex_to_bytes("e8e99d0f45237d786d6bbaa7965c7808bbff1a91", expected, HMAC_SHA1_LEN);
  hmac_sha1(key, sizeof(key), data, 73, out);
  ASSERT_TRUE(check(out, expected) == 0);
}

TEST_GROUP(hmac)
{
TEST(test_rfc2202_1),
      TEST(test_rfc2202_2),
      TEST(test_rfc2202_3),
      TEST(test_rfc2202_4), TEST(test_rfc2202_5), TEST(test_rfc2202_6), TEST(test_rfc2202_7), END_TEST};
