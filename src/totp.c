#include "totp.h"

uint32_t totp_generate(const unsigned char *secret, size_t secret_len,
                       uint64_t counter, int digits)
{
    (void)secret;
    (void)secret_len;
    (void)counter;
    (void)digits;
    return 0;
}

int totp_validate(const unsigned char *secret, size_t secret_len,
                  uint32_t token, int digits, int step,
                  int drift_behind, int drift_ahead, time_t now)
{
    (void)secret;
    (void)secret_len;
    (void)token;
    (void)digits;
    (void)step;
    (void)drift_behind;
    (void)drift_ahead;
    (void)now;
    return -1;
}
