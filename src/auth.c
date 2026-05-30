#include "auth.h"
#include "totp.h"

#include <errno.h>
#include <string.h>

#define REPLAY_TABLE_SIZE 64
#define REPLAY_TABLE_MASK 63
#define MAX_PACKET_LEN 256
#define MAX_TOKEN_DIGITS 8
#define MIN_TOKEN_DIGITS 6

struct replay_entry {
  uint32_t ip;
  uint64_t last_seq;
  time_t last_seen;
  int used;
};

static struct replay_entry g_replay[REPLAY_TABLE_SIZE];

static size_t replay_idx(uint32_t ip)
{
  uint32_t h = ip;

  h ^= h >> 16;
  h ^= h >> 8;
  h ^= h >> 4;
  return (size_t)(h & REPLAY_TABLE_MASK);
}

int auth_seen_before(uint64_t seq, uint32_t src_ip)
{
  size_t idx = replay_idx(src_ip);
  size_t i;

  for (i = 0; i < REPLAY_TABLE_SIZE; i++) {
    size_t pos = (idx + i) & REPLAY_TABLE_MASK;

    if (!g_replay[pos].used)
      return 0;
    if (g_replay[pos].ip == src_ip) {
      if (seq <= g_replay[pos].last_seq)
        return -1;
      return 0;
    }
  }
  return 0;
}

int auth_record_seq(uint64_t seq, uint32_t src_ip)
{
  size_t idx = replay_idx(src_ip);
  size_t first_empty = REPLAY_TABLE_SIZE;
  size_t i;

  for (i = 0; i < REPLAY_TABLE_SIZE; i++) {
    size_t pos = (idx + i) & REPLAY_TABLE_MASK;

    if (!g_replay[pos].used) {
      if (first_empty >= REPLAY_TABLE_SIZE)
        first_empty = pos;
      break;
    }
    if (g_replay[pos].ip == src_ip) {
      g_replay[pos].last_seq = seq;
      g_replay[pos].last_seen = time(NULL);
      return 0;
    }
  }

  if (first_empty < REPLAY_TABLE_SIZE) {
    g_replay[first_empty].ip = src_ip;
    g_replay[first_empty].last_seq = seq;
    g_replay[first_empty].last_seen = time(NULL);
    g_replay[first_empty].used = 1;
    return 0;
  }

  errno = ENOSPC;
  return -1;
}

void auth_replay_reset(void)
{
  memset(g_replay, 0, sizeof(g_replay));
}

void auth_replay_prune(time_t now, time_t max_age)
{
  size_t i;

  for (i = 0; i < REPLAY_TABLE_SIZE; i++) {
    if (g_replay[i].used && now - g_replay[i].last_seen > max_age) {
      g_replay[i].used = 0;
    }
  }
}

/* ---- packet parser ---- */

int auth_parse(const unsigned char *data, size_t len, uint32_t *token)
{
  size_t i = 0;
  uint32_t t = 0;
  size_t token_len = 0;

  if (data == NULL || len == 0 || len > MAX_PACKET_LEN)
    return -1;

  while (i < len && data[i] >= '0' && data[i] <= '9') {
    if (token_len >= MAX_TOKEN_DIGITS)
      return -1;
    t = t * 10 + (uint32_t) (data[i] - '0');
    token_len++;
    i++;
  }

  if (token_len < MIN_TOKEN_DIGITS || token_len > MAX_TOKEN_DIGITS)
    return -1;

  if (i != len)
    return -1;

  if (token)
    *token = t;

  return 0;
}

int auth_validate(const unsigned char *secret, size_t secret_len,
                  uint32_t token, uint32_t src_ip, time_t now, int digits, int step, int drift_behind, int drift_ahead)
{
  uint64_t current = (uint64_t) now / (uint64_t) step;
  int d;

  for (d = -drift_behind; d <= drift_ahead; d++) {
    uint64_t counter;

    if (d < 0 && current < (uint64_t) (-d))
      continue;

    counter = (uint64_t) ((int64_t) current + d);

    if (totp_generate(secret, secret_len, counter, digits) == token) {
      if (auth_seen_before(counter, src_ip) != 0)
        return -1;
      if (auth_record_seq(counter, src_ip) != 0)
        return -1;
      return 0;
    }
  }

  return -1;
}
