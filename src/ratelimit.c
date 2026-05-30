#include "ratelimit.h"

#include <string.h>

#define RATE_TABLE_SIZE 64
#define RATE_TABLE_MASK 63

struct rate_entry {
  uint32_t ip;
  uint32_t fail_count;
  time_t first_fail;
  time_t block_until;
  uint32_t block_duration;
  int used;
};

static struct rate_entry g_table[RATE_TABLE_SIZE];

static size_t rate_idx(uint32_t ip)
{
  uint32_t h = ip;

  h ^= h >> 16;
  h ^= h >> 8;
  h ^= h >> 4;
  return (size_t)(h & RATE_TABLE_MASK);
}

int rate_limit_check(uint32_t ip, time_t now)
{
  size_t idx = rate_idx(ip);
  size_t i;

  for (i = 0; i < RATE_TABLE_SIZE; i++) {
    size_t pos = (idx + i) & RATE_TABLE_MASK;

    if (!g_table[pos].used)
      return 0;
    if (g_table[pos].ip == ip) {
      if (now < g_table[pos].block_until)
        return -1;
      return 0;
    }
  }
  return 0;
}

static uint32_t calc_block_duration(uint32_t current, const struct rate_limit_cfg *cfg)
{
  if (current == 0)
    return cfg->min_block;
  {
    uint32_t next = current * 2;

    if (next > cfg->max_block)
      return cfg->max_block;
    return next;
  }
}

void rate_limit_fail(uint32_t ip, time_t now, const struct rate_limit_cfg *cfg)
{
  size_t idx = rate_idx(ip);
  size_t first_empty = RATE_TABLE_SIZE;
  size_t i;

  for (i = 0; i < RATE_TABLE_SIZE; i++) {
    size_t pos = (idx + i) & RATE_TABLE_MASK;

    if (!g_table[pos].used) {
      if (first_empty >= RATE_TABLE_SIZE)
        first_empty = pos;
      break;
    }

    if (g_table[pos].ip == ip) {
      if (now - g_table[pos].first_fail > (time_t) cfg->window) {
        g_table[pos].fail_count = 1;
        g_table[pos].first_fail = now;
        return;
      }

      g_table[pos].fail_count++;
      if (g_table[pos].fail_count >= cfg->max_fails && now >= g_table[pos].block_until) {
        g_table[pos].block_duration = calc_block_duration(g_table[pos].block_duration, cfg);
        g_table[pos].block_until = now + (time_t) g_table[pos].block_duration;
      }
      return;
    }
  }

  if (first_empty < RATE_TABLE_SIZE) {
    g_table[first_empty].ip = ip;
    g_table[first_empty].fail_count = 1;
    g_table[first_empty].first_fail = now;
    g_table[first_empty].block_until = 0;
    g_table[first_empty].block_duration = 0;
    g_table[first_empty].used = 1;
  }
}

void rate_limit_success(uint32_t ip)
{
  size_t idx = rate_idx(ip);
  size_t i;

  for (i = 0; i < RATE_TABLE_SIZE; i++) {
    size_t pos = (idx + i) & RATE_TABLE_MASK;

    if (!g_table[pos].used)
      return;
    if (g_table[pos].ip == ip) {
      g_table[pos].used = 0;
      return;
    }
  }
}

void rate_limit_reset(void)
{
  memset(g_table, 0, sizeof(g_table));
}
