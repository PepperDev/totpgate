#include "totp.h"
#include "hmac.h"

#include <string.h>

static uint32_t pow10(int digits)
{
    if (digits == 6)
        return 1000000;
    if (digits == 7)
        return 10000000;
    if (digits == 8)
        return 100000000;
    return 1000000;
}

static uint32_t hotp(const unsigned char *secret, size_t secret_len,
                     uint64_t counter, int digits)
{
    unsigned char counter_be[8];
    unsigned char mac[HMAC_SHA1_LEN];
    int offset;
    uint32_t binary;
    size_t i;

    for (i = 0; i < 8; i++) {
        counter_be[7 - i] = (unsigned char)(counter & 0xff);
        counter >>= 8;
    }

    hmac_sha1(secret, secret_len, counter_be, 8, mac);

    offset = mac[HMAC_SHA1_LEN - 1] & 0x0f;
    binary = ((uint32_t)(mac[offset] & 0x7f) << 24)
           | ((uint32_t)mac[offset + 1] << 16)
           | ((uint32_t)mac[offset + 2] << 8)
           | (uint32_t)mac[offset + 3];

    return binary % pow10(digits);
}

uint32_t totp_generate(const unsigned char *secret, size_t secret_len,
                       uint64_t counter, int digits)
{
    return hotp(secret, secret_len, counter, digits);
}

int totp_validate(const unsigned char *secret, size_t secret_len,
                  uint32_t token, int digits, int step,
                  int drift_behind, int drift_ahead, time_t now,
                  uint64_t *out_counter)
{
    uint64_t current = (uint64_t)now / (uint64_t)step;
    int d;

    for (d = -drift_behind; d <= drift_ahead; d++) {
        uint64_t candidate;

        if (d < 0 && current < (uint64_t)(-d))
            continue;

        candidate = (uint64_t)((int64_t)current + d);

        if (hotp(secret, secret_len, candidate, digits) == token) {
            if (out_counter)
                *out_counter = candidate;
            return 0;
        }
    }

    return -1;
}
