#ifndef CLIENT_H
#define CLIENT_H

#include <stddef.h>
#include <stdint.h>

struct client_cfg {
  unsigned char secret[256];
  size_t secret_len;
  uint16_t port;
  char server[256];
};

int parse_args(struct client_cfg *cfg, int argc, char *argv[]);
int client_run(struct client_cfg *cfg);

#endif
