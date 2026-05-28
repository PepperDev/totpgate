#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>

#define SHA1_DIGEST_LEN 20

void sha1(const unsigned char *msg, size_t len, unsigned char out[SHA1_DIGEST_LEN]);

#endif
