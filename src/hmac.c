#include "hmac.h"
#include "sha1.h"

#include <string.h>

void hmac_sha1(const unsigned char *key, size_t key_len,
               const unsigned char *msg, size_t msg_len,
               unsigned char out[HMAC_SHA1_LEN])
{
    unsigned char k[SHA1_BLOCK_LEN];
    unsigned char inner[SHA1_DIGEST_LEN];
    sha1_ctx_t ctx;
    size_t i;

    if (key_len > SHA1_BLOCK_LEN) {
        sha1(key, key_len, k);
        memset(k + SHA1_DIGEST_LEN, 0,
               SHA1_BLOCK_LEN - SHA1_DIGEST_LEN);
    } else {
        memcpy(k, key, key_len);
        if (key_len < SHA1_BLOCK_LEN) {
            memset(k + key_len, 0,
                   SHA1_BLOCK_LEN - key_len);
        }
    }

    for (i = 0; i < SHA1_BLOCK_LEN; i++) {
        k[i] ^= 0x36;
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k, SHA1_BLOCK_LEN);
    sha1_update(&ctx, msg, msg_len);
    sha1_final(&ctx, inner);

    for (i = 0; i < SHA1_BLOCK_LEN; i++) {
        k[i] ^= 0x36;
    }

    for (i = 0; i < SHA1_BLOCK_LEN; i++) {
        k[i] ^= 0x5c;
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k, SHA1_BLOCK_LEN);
    sha1_update(&ctx, inner, SHA1_DIGEST_LEN);
    sha1_final(&ctx, out);
}
