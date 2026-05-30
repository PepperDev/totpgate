#ifndef PARSE_OPTS_H
#define PARSE_OPTS_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <net/if.h>
#include "ratelimit.h"

#define SECRET_FILE_MAX 4096
#define MAX_PORTS 8

struct listen_addr {
  struct sockaddr_storage addr;
  socklen_t addrlen;
};

struct config {
  struct listen_addr ports[MAX_PORTS];
  int num_ports;
  uint16_t target_port;
  unsigned char secret[256];
  size_t secret_len;
  uint32_t timeout;
  char user[32];
  char group[32];
  char iface[IFNAMSIZ];
  char secret_file[SECRET_FILE_MAX];
  int foreground;
  int test_mode;
  struct rate_limit_cfg rate_limit;
};

int parse_daemon_args(struct config *cfg, int argc, char *argv[]);

#endif
