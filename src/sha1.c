#include "sha1.h"

#include <string.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void process_block(sha1_ctx_t *ctx)
{
  uint32_t W[80];
  uint32_t A, B, C, D, E;
  int t;

  for (t = 0; t < 16; t++) {
    W[t] = ((uint32_t) ctx->buf[t * 4] << 24)
        | ((uint32_t) ctx->buf[t * 4 + 1] << 16)
        | ((uint32_t) ctx->buf[t * 4 + 2] << 8)
        | (uint32_t) ctx->buf[t * 4 + 3];
  }
  for (t = 16; t < 80; t++) {
    W[t] = ROTL(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1);
  }

  A = ctx->H[0];
  B = ctx->H[1];
  C = ctx->H[2];
  D = ctx->H[3];
  E = ctx->H[4];

  for (t = 0; t < 80; t++) {
    uint32_t f, k;
    if (t < 20) {
      f = (B & C) | ((~B) & D);
      k = 0x5a827999;
    } else if (t < 40) {
      f = B ^ C ^ D;
      k = 0x6ed9eba1;
    } else if (t < 60) {
      f = (B & C) | (B & D) | (C & D);
      k = 0x8f1bbcdc;
    } else {
      f = B ^ C ^ D;
      k = 0xca62c1d6;
    }
    uint32_t temp = ROTL(A, 5) + f + E + k + W[t];
    E = D;
    D = C;
    C = ROTL(B, 30);
    B = A;
    A = temp;
  }

  ctx->H[0] += A;
  ctx->H[1] += B;
  ctx->H[2] += C;
  ctx->H[3] += D;
  ctx->H[4] += E;
}

void sha1_init(sha1_ctx_t *ctx)
{
  ctx->H[0] = 0x67452301;
  ctx->H[1] = 0xefcdab89;
  ctx->H[2] = 0x98badcfe;
  ctx->H[3] = 0x10325476;
  ctx->H[4] = 0xc3d2e1f0;
  ctx->count = 0;
}

void sha1_update(sha1_ctx_t *ctx, const unsigned char *data, size_t len)
{
  size_t idx = (size_t)(ctx->count % SHA1_BLOCK_LEN);

  ctx->count += len;

  if (idx > 0) {
    size_t avail = SHA1_BLOCK_LEN - idx;
    if (len < avail) {
      memcpy(ctx->buf + idx, data, len);
      return;
    }
    memcpy(ctx->buf + idx, data, avail);
    process_block(ctx);
    data += avail;
    len -= avail;
  }

  while (len >= SHA1_BLOCK_LEN) {
    memcpy(ctx->buf, data, SHA1_BLOCK_LEN);
    process_block(ctx);
    data += SHA1_BLOCK_LEN;
    len -= SHA1_BLOCK_LEN;
  }

  if (len > 0) {
    memcpy(ctx->buf, data, len);
  }
}

void sha1_final(sha1_ctx_t *ctx, unsigned char out[SHA1_DIGEST_LEN])
{
  uint64_t bits = ctx->count * 8;
  size_t idx = (size_t)(ctx->count % SHA1_BLOCK_LEN);
  size_t i;

  ctx->buf[idx] = 0x80;
  idx++;

  if (idx > 56) {
    memset(ctx->buf + idx, 0, SHA1_BLOCK_LEN - idx);
    process_block(ctx);
    idx = 0;
  }

  memset(ctx->buf + idx, 0, 56 - idx);

  for (i = 0; i < 8; i++) {
    ctx->buf[56 + i] = (unsigned char)(bits >> (56 - i * 8));
  }

  process_block(ctx);

  for (i = 0; i < 5; i++) {
    out[i * 4] = (unsigned char)(ctx->H[i] >> 24);
    out[i * 4 + 1] = (unsigned char)(ctx->H[i] >> 16);
    out[i * 4 + 2] = (unsigned char)(ctx->H[i] >> 8);
    out[i * 4 + 3] = (unsigned char)(ctx->H[i]);
  }
}

void sha1(const unsigned char *msg, size_t len, unsigned char out[SHA1_DIGEST_LEN])
{
  sha1_ctx_t ctx;

  sha1_init(&ctx);
  sha1_update(&ctx, msg, len);
  sha1_final(&ctx, out);
}
