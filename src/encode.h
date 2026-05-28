#ifndef ENCODE_H
#define ENCODE_H

#include <stddef.h>

enum secret_encoding {
  SECRET_BASE32 = 0,
  SECRET_HEX,
  SECRET_BASE64,
};

int secret_decode(const char *input, unsigned char *out, size_t *out_len, enum secret_encoding *encoding);

#endif
