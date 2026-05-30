#ifndef TOTP_H
#define TOTP_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "addr.h"

struct totp_params {
  ip_addr_t src_ip;
  time_t now;
  int digits;
  int step;
  int drift_behind;
  int drift_ahead;
  uint64_t *out_counter;
};

uint32_t totp_generate(const unsigned char *secret, size_t secret_len, uint64_t counter, int digits);

int totp_validate(const unsigned char *secret, size_t secret_len, uint32_t token, const struct totp_params *p);

#endif
