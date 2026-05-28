#include "encode.h"
#include <string.h>

/* ---- character lookup helpers ---- */

static int hex_val(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int b32_val(char c)
{
    if (c >= 'a' && c <= 'z') c -= 32;
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    if (c == '=') return -2;
    return -1;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    if (c == '=') return -2;
    return -1;
}

/* hex_decode maps count of hex chars to output bytes (floor division) */
#define HEX_PAIRS(n)  ((n) / 2)

static int hex_decode(const char *in, size_t in_len,
                      unsigned char *out, size_t *out_len)
{
    size_t max = *out_len;
    size_t pos = 0;
    size_t i;

    if (in_len == 0) {
        *out_len = 0;
        return 0;
    }

    for (i = 0; i + 1 < in_len; i += 2) {
        int hi = hex_val(in[i]);
        int lo = hex_val(in[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        if (pos >= max) return -1;
        out[pos++] = (unsigned char)((hi << 4) | lo);
    }

    if (i < in_len) {
        int hi = hex_val(in[i]);
        if (hi < 0) return -1;
        if (pos >= max) return -1;
        out[pos++] = (unsigned char)(hi << 4);
    }

    *out_len = pos;
    return 0;
}

/* base32_decode output bytes per group of 8 input chars (indexed by
   number of non-padding chars: 0,2,4,5,7,8 → 0,1,2,3,4,5) */
static const unsigned char b32_tab[9] = {
    [0] = 0, [2] = 1, [4] = 2, [5] = 3, [7] = 4, [8] = 5,
};

static int base32_decode(const char *in, size_t in_len,
                         unsigned char *out, size_t *out_len)
{
    size_t max = *out_len;
    size_t pos = 0;
    size_t i = 0;

    if (in_len == 0) {
        *out_len = 0;
        return 0;
    }

    while (i < in_len) {
        int vals[8];
        int j;
        int n;
        int m;
        unsigned long bits;

        for (j = 0; j < 8; j++) {
            if (i >= in_len) {
                m = j;
                n = b32_tab[m];
                if (n == 0) return -1;
                for (; j < 8; j++) vals[j] = 0;
                goto emit;
            }
            int v = b32_val(in[i]);
            if (v == -2) {
                m = j;
                n = b32_tab[m];
                if (n == 0) return -1;
                for (; j < 8; j++) {
                    if (i < in_len && in[i] != '=') return -1;
                    vals[j] = 0;
                    i++;
                }
                goto emit;
            }
            if (v < 0) return -1;
            vals[j] = v;
            i++;
        }
        m = 8;
        n = 5;

emit:
        if (pos + n > max) return -1;

        bits = 0;
        for (j = 0; j < 8; j++) {
            bits = (bits << 5) | (unsigned)(vals[j] & 0x1f);
        }

        /* validate unused trailing bits in partial group */
        if (m < 8) {
            int leftover = m * 5 - n * 8;
            if ((vals[m - 1] & ((1 << leftover) - 1)) != 0) return -1;
        }

        for (j = 0; j < n; j++) {
            out[pos++] = (unsigned char)(bits >> (32 - j * 8));
        }
    }

    *out_len = pos;
    return 0;
}

/* base64_decode output bytes per group of 4 input chars */
#define B64_GROUP(n)  (((n) * 3) / 4)

static int base64_decode(const char *in, size_t in_len,
                         unsigned char *out, size_t *out_len)
{
    size_t max = *out_len;
    size_t pos = 0;
    size_t i = 0;

    if (in_len == 0) {
        *out_len = 0;
        return 0;
    }

    while (i < in_len) {
        int vals[4];
        int j;
        int n;
        unsigned long bits;

        for (j = 0; j < 4; j++) {
            if (i >= in_len) {
                n = B64_GROUP(j);
                if (n == 0) return -1;
                for (; j < 4; j++) vals[j] = 0;
                goto emit64;
            }
            int v = b64_val(in[i]);
            if (v == -2) {
                n = B64_GROUP(j);
                if (n == 0) return -1;
                for (; j < 4; j++) {
                    if (i < in_len && in[i] != '=') return -1;
                    vals[j] = 0;
                    i++;
                }
                goto emit64;
            }
            if (v < 0) return -1;
            vals[j] = v;
            i++;
        }
        n = 3;

emit64:
        if (pos + n > max) return -1;

        bits = 0;
        for (j = 0; j < 4; j++) {
            bits = (bits << 6) | (unsigned)(vals[j] & 0x3f);
        }

        for (j = 0; j < n; j++) {
            out[pos++] = (unsigned char)(bits >> (16 - j * 8));
        }
    }

    *out_len = pos;
    return 0;
}

/* ---- public API ---- */

int secret_decode(const char *input, unsigned char *out, size_t *out_len,
                  enum secret_encoding *encoding)
{
    size_t len;

    if (input == NULL || out == NULL || out_len == NULL || encoding == NULL) {
        return -1;
    }

    len = strlen(input);
    if (len == 0) {
        *out_len = 0;
        *encoding = SECRET_BASE32;
        return 0;
    }

    if (len >= 4 && input[0] == 'h' && input[1] == 'e' && input[2] == 'x'
        && input[3] == ':') {
        *encoding = SECRET_HEX;
        return hex_decode(input + 4, len - 4, out, out_len);
    }

    if (len >= 4 && input[0] == 'b' && input[1] == '6' && input[2] == '4'
        && input[3] == ':') {
        *encoding = SECRET_BASE64;
        return base64_decode(input + 4, len - 4, out, out_len);
    }

    *encoding = SECRET_BASE32;
    return base32_decode(input, len, out, out_len);
}
