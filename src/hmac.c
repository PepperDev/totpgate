#include "hmac.h"

void hmac_sha1(const unsigned char *key, size_t key_len,
               const unsigned char *msg, size_t msg_len,
               unsigned char out[HMAC_SHA1_LEN])
{
    (void)key;
    (void)key_len;
    (void)msg;
    (void)msg_len;
    (void)out;
}
