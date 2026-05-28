#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_LEN 20
#define SHA1_BLOCK_LEN  64

typedef struct {
  uint32_t H[5];
  uint64_t count;
  unsigned char buf[SHA1_BLOCK_LEN];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t * ctx);
void sha1_update(sha1_ctx_t * ctx, const unsigned char *data, size_t len);
void sha1_final(sha1_ctx_t * ctx, unsigned char out[SHA1_DIGEST_LEN]);

void sha1(const unsigned char *msg, size_t len, unsigned char out[SHA1_DIGEST_LEN]);

#endif
