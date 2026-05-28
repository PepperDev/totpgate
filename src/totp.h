#ifndef TOTP_H
#define TOTP_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

uint32_t totp_generate(const unsigned char *secret, size_t secret_len,
                       uint64_t counter, int digits);

int totp_validate(const unsigned char *secret, size_t secret_len,
                  uint32_t token, int digits, int step,
                  int drift_behind, int drift_ahead, time_t now);

#endif
