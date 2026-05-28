#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include <time.h>

struct rate_limit_cfg {
  uint32_t min_block;
  uint32_t max_block;
  uint32_t max_fails;
  uint32_t window;
};

int rate_limit_check(uint32_t ip, time_t now);
void rate_limit_fail(uint32_t ip, time_t now, const struct rate_limit_cfg *cfg);
void rate_limit_success(uint32_t ip);
void rate_limit_reset(void);

#endif
