#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include "encode.h"
#include "netlink.h"
#include "udp.h"
#include "auth.h"

struct config {
    uint16_t control_port;
    uint16_t target_port;
    unsigned char secret[256];
    size_t secret_len;
    uint32_t timeout;
    int foreground;
};

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --secret <secret> [options]\n"
        "\n"
        "Options:\n"
        "  --control-port <port>   UDP listen port (default: 2222)\n"
        "  --port <port>           Target TCP port (default: 22)\n"
        "  --secret <secret>       Shared secret\n"
        "                          (base32 by default; prefix with\n"
        "                           hex: or b64: for other encodings)\n"
        "  --timeout <seconds>     Rule lifetime (default: 30)\n"
        "  --foreground            Log to stderr instead of syslog\n"
        "  --help                  Show this help\n",
        prog);
}

static int parse_args(struct config *cfg, int argc, char *argv[])
{
    static const struct option long_opts[] = {
        { "control-port", required_argument, NULL, 'c' },
        { "port",         required_argument, NULL, 'p' },
        { "secret",       required_argument, NULL, 's' },
        { "timeout",      required_argument, NULL, 't' },
        { "foreground",   no_argument,       NULL, 'f' },
        { "help",         no_argument,       NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };
    int opt;
    int secret_given = 0;

    while ((opt = getopt_long(argc, argv, "c:p:s:t:fh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'c': {
            long val = atol(optarg);
            if (val < 1 || val > 65535) {
                fprintf(stderr, "error: --control-port must be 1-65535\n");
                return -1;
            }
            cfg->control_port = (uint16_t)val;
            break;
        }
        case 'p': {
            long val = atol(optarg);
            if (val < 1 || val > 65535) {
                fprintf(stderr, "error: --port must be 1-65535\n");
                return -1;
            }
            cfg->target_port = (uint16_t)val;
            break;
        }
        case 's': {
            size_t out_len = sizeof(cfg->secret);
            enum secret_encoding enc;
            if (secret_decode(optarg, cfg->secret, &out_len, &enc) != 0) {
                fprintf(stderr, "error: invalid --secret encoding\n");
                return -1;
            }
            cfg->secret_len = out_len;
            secret_given = 1;
            break;
        }
        case 't': {
            long val = atol(optarg);
            if (val < 1 || val > 86400) {
                fprintf(stderr, "error: --timeout must be 1-86400\n");
                return -1;
            }
            cfg->timeout = (uint32_t)val;
            break;
        }
        case 'f':
            cfg->foreground = 1;
            break;
        case 'h':
            print_usage(argv[0]);
            exit(0);
        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (!secret_given) {
        fprintf(stderr, "error: --secret is required\n");
        print_usage(argv[0]);
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    struct config cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.control_port = 2222;
    cfg.target_port = 22;
    cfg.timeout = 30;

    if (parse_args(&cfg, argc, argv) != 0) {
        return 1;
    }

    fprintf(stderr, "control_port=%u\n", cfg.control_port);
    fprintf(stderr, "target_port=%u\n", cfg.target_port);
    fprintf(stderr, "secret_len=%zu\n", cfg.secret_len);
    fprintf(stderr, "timeout=%u\n", cfg.timeout);
    fprintf(stderr, "foreground=%d\n", cfg.foreground);

    return 0;
}
