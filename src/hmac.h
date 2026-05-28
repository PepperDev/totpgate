#ifndef HMAC_H
#define HMAC_H

#include <stddef.h>

#define HMAC_SHA1_LEN 20

void hmac_sha1(const unsigned char *key, size_t key_len,
               const unsigned char *msg, size_t msg_len, unsigned char out[HMAC_SHA1_LEN]);

#endif
