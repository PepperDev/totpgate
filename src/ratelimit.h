#ifndef RATELIMIT_H
#define RATELIMIT_H

#include <stdint.h>
#include <time.h>
#include "addr.h"

struct rate_limit_cfg {
  uint32_t min_block;
  uint32_t max_block;
  uint32_t max_fails;
  uint32_t window;
};

int rate_limit_check(const ip_addr_t * ip, time_t now);
void rate_limit_fail(const ip_addr_t * ip, time_t now, const struct rate_limit_cfg *cfg);
void rate_limit_success(const ip_addr_t * ip);
void rate_limit_reset(void);

#endif
