#include "test_runner.h"
#include "encode.h"
#include <string.h>

/* ---- hex decode ---- */

static void hex_empty(void)
{
  unsigned char out[4];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 0);
}

static void hex_foo(void)
{
  unsigned char out[4];
  size_t len = sizeof(out);
  enum secret_encoding enc;
  ASSERT_INT_EQ(secret_decode("hex:666f6f", out, &len, &enc), 0);
  ASSERT_INT_EQ((int)enc, (int)SECRET_HEX);
  ASSERT_INT_EQ((int)len, 3);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
}

static void hex_odd_length(void)
{
  unsigned char out[4];
  size_t len = sizeof(out);
  enum secret_encoding enc;
  ASSERT_INT_EQ(secret_decode("hex:abc", out, &len, &enc), 0);
  ASSERT_INT_EQ((int)len, 2);
  ASSERT_INT_EQ((int)out[0], 0xab);
  ASSERT_INT_EQ((int)out[1], 0xc0);
}

static void hex_uppercase(void)
{
  unsigned char out[4];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("hex:FF", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 1);
  ASSERT_INT_EQ((int)out[0], 0xff);
}

static void hex_invalid_char(void)
{
  unsigned char out[4];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("hex:zz", out, &len, &(enum secret_encoding) { 0 }), -1);
}

/* ---- base32 decode ---- */

static void b32_empty(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 0);
}

static void b32_f(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  enum secret_encoding enc;
  ASSERT_INT_EQ(secret_decode("MY======", out, &len, &enc), 0);
  ASSERT_INT_EQ((int)enc, (int)SECRET_BASE32);
  ASSERT_INT_EQ((int)len, 1);
  ASSERT_INT_EQ((int)out[0], 'f');
}

static void b32_fo(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXQ====", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 2);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
}

static void b32_foo(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXW6===", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 3);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
}

static void b32_foob(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXW6YQ=", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 4);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
  ASSERT_INT_EQ((int)out[3], 'b');
}

static void b32_fooba(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXW6YTB", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 5);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
  ASSERT_INT_EQ((int)out[3], 'b');
  ASSERT_INT_EQ((int)out[4], 'a');
}

static void b32_foobar(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXW6YTBOI======", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 6);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
  ASSERT_INT_EQ((int)out[3], 'b');
  ASSERT_INT_EQ((int)out[4], 'a');
  ASSERT_INT_EQ((int)out[5], 'r');
}

static void b32_lowercase(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("mzxw6ytboi======", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 6);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
  ASSERT_INT_EQ((int)out[3], 'b');
  ASSERT_INT_EQ((int)out[4], 'a');
  ASSERT_INT_EQ((int)out[5], 'r');
}

static void b32_invalid_char(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZX!====", out, &len, &(enum secret_encoding) { 0 }), -1);
}

static void b32_bad_padding(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXW6===", out, &len, &(enum secret_encoding) { 0 }), 0);
  len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("MZXW6YT", out, &len, &(enum secret_encoding) { 0 }), -1);
}

/* ---- base64 decode ---- */

static void b64_empty(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("b64:", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 0);
}

static void b64_f(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  enum secret_encoding enc;
  ASSERT_INT_EQ(secret_decode("b64:Zg==", out, &len, &enc), 0);
  ASSERT_INT_EQ((int)enc, (int)SECRET_BASE64);
  ASSERT_INT_EQ((int)len, 1);
  ASSERT_INT_EQ((int)out[0], 'f');
}

static void b64_fo(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("b64:Zm8=", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 2);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
}

static void b64_foo(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("b64:Zm9v", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 3);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
}

static void b64_foobar(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("b64:Zm9vYmFy", out, &len, &(enum secret_encoding) { 0 }), 0);
  ASSERT_INT_EQ((int)len, 6);
  ASSERT_INT_EQ((int)out[0], 'f');
  ASSERT_INT_EQ((int)out[1], 'o');
  ASSERT_INT_EQ((int)out[2], 'o');
  ASSERT_INT_EQ((int)out[3], 'b');
  ASSERT_INT_EQ((int)out[4], 'a');
  ASSERT_INT_EQ((int)out[5], 'r');
}

static void b64_invalid_char(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode("b64:Zm$v", out, &len, &(enum secret_encoding) { 0 }), -1);
}

/* ---- error cases ---- */

static void null_input(void)
{
  unsigned char out[4];
  size_t len = sizeof(out);
  ASSERT_INT_EQ(secret_decode(NULL, out, &len, &(enum secret_encoding) { 0 }), -1);
}

static void buffer_too_small(void)
{
  unsigned char out[2];
  size_t len = 1;
  ASSERT_INT_EQ(secret_decode("MZXW6YTB", out, &len, &(enum secret_encoding) { 0 }), -1);
}

static void unknown_prefix(void)
{
  unsigned char out[16];
  size_t len = sizeof(out);
  enum secret_encoding enc;
  ASSERT_INT_EQ(secret_decode("JBSWY3DPEHPK3PXP", out, &len, &enc), 0);
  ASSERT_INT_EQ((int)enc, (int)SECRET_BASE32);
}

/* ---- register tests ---- */

TEST_GROUP(encode)
{
TEST(hex_empty),
      TEST(hex_foo),
      TEST(hex_odd_length),
      TEST(hex_uppercase),
      TEST(hex_invalid_char),
      TEST(b32_empty),
      TEST(b32_f),
      TEST(b32_fo),
      TEST(b32_foo),
      TEST(b32_foob),
      TEST(b32_fooba),
      TEST(b32_foobar),
      TEST(b32_lowercase),
      TEST(b32_invalid_char),
      TEST(b32_bad_padding),
      TEST(b64_empty),
      TEST(b64_f),
      TEST(b64_fo),
      TEST(b64_foo),
      TEST(b64_foobar),
      TEST(b64_invalid_char), TEST(null_input), TEST(buffer_too_small), TEST(unknown_prefix), END_TEST};
