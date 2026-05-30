#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

int auth_parse(const unsigned char *data, size_t len, uint32_t * token);

int auth_validate(const unsigned char *secret, size_t secret_len,
                  uint32_t token, uint32_t src_ip, time_t now, int digits, int step, int drift_behind, int drift_ahead);

int auth_seen_before(uint64_t seq, uint32_t src_ip);

int auth_record_seq(uint64_t seq, uint32_t src_ip);

void auth_replay_reset(void);

void auth_replay_prune(time_t now, time_t max_age);

#endif
