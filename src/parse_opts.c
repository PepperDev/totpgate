#include "parse_opts.h"
#include "encode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int parse_addr_str(const char *s, char *node, size_t node_sz, const char **port_str)
{
  if (s[0] == '[') {
    const char *close = strchr(s, ']');
    if (!close || *(close + 1) != ':')
      return -1;
    {
      size_t nlen = (size_t)(close - s - 1);
      if (nlen >= node_sz)
        return -1;
      memcpy(node, s + 1, nlen);
      node[nlen] = '\0';
    }
    *port_str = close + 2;
  } else {
    const char *colon = strrchr(s, ':');
    if (colon) {
      size_t nlen = (size_t)(colon - s);
      if (nlen >= node_sz)
        return -1;
      memcpy(node, s, nlen);
      node[nlen] = '\0';
      *port_str = colon + 1;
    } else {
      node[0] = '\0';
      *port_str = s;
    }
  }
  return 0;
}

static int parse_listen_addr(const char *s, struct listen_addr *la)
{
  char node[256];
  const char *port_str;
  struct addrinfo hints, *res;
  int ret;

  if (parse_addr_str(s, node, sizeof(node), &port_str) != 0)
    return -1;

  {
    long val = atol(port_str);
    if (val < 1 || val > 65535)
      return -1;
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;

  if (node[0] != '\0') {
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
    hints.ai_family = AF_UNSPEC;
  } else {
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_INET6;
  }

  ret = getaddrinfo(node[0] ? node : NULL, port_str, &hints, &res);
  if (ret != 0)
    return -1;

  if ((size_t)res->ai_addrlen > sizeof(la->addr)) {
    freeaddrinfo(res);
    return -1;
  }

  memcpy(&la->addr, res->ai_addr, res->ai_addrlen);
  la->addrlen = res->ai_addrlen;
  freeaddrinfo(res);
  return 0;
}

static void print_usage(const char *prog)
{
  fprintf(stderr,
          "Usage: %s --secret <secret> [options]\n"
          "\n"
          "Options:\n"
          "  --port <[ip:]port>      UDP listen port (default: 2222)\n"
          "                          May be given multiple times with optional\n"
          "                          IP binding (e.g. 0.0.0.0:2222, [::]:2222)\n"
          "  --target-port <port>    TCP application port to protect (default: 22)\n"
          "  --secret <secret>       Shared secret (mutually exclusive with --secret-file)\n"
          "                          (base32 by default; prefix with\n"
          "                           hex: or b64: for other encodings)\n"
          "  --secret-file <path>    Read secret from file (mutually exclusive with --secret)\n"
          "  --timeout <seconds>     Rule lifetime (default: 30)\n"
          "  --min-block <seconds>   Min rate-limit block duration (default: 300)\n"
          "  --max-block <seconds>   Max rate-limit block duration (default: 86400)\n"
          "  --rate-limit <n/window> Max fails per window (default: 5/60)\n"
          "  --interface <name>      Network interface to bind firewall rules to\n"
          "  --user <user>           Drop privileges to this user (default: nobody)\n"
          "  --group <group>         Use this group after dropping privs (default: nogroup)\n"
          "  --foreground            Log to stderr instead of syslog\n"
          "  --help                  Show this help\n", prog);
}

static int handle_port_opt(struct config *cfg, const char *optarg)
{
  char node[256];
  const char *port_str;

  if (parse_addr_str(optarg, node, sizeof(node), &port_str) != 0) {
    fprintf(stderr, "error: invalid --port '%s'\n", optarg);
    return -1;
  }

  if (node[0] == '\0') {
    long val = atol(port_str);
    if (val < 1 || val > 65535) {
      fprintf(stderr, "error: invalid --port '%s'\n", optarg);
      return -1;
    }
    if (cfg->num_ports >= MAX_PORTS - 1) {
      fprintf(stderr, "error: too many --port arguments (max %d)\n", MAX_PORTS);
      return -1;
    }

    {
      struct sockaddr_in *in4 = (struct sockaddr_in *)&cfg->ports[cfg->num_ports].addr;
      memset(in4, 0, sizeof(*in4));
      in4->sin_family = AF_INET;
      in4->sin_port = htons((uint16_t)val);
      in4->sin_addr.s_addr = htonl(INADDR_ANY);
      cfg->ports[cfg->num_ports].addrlen = sizeof(*in4);
      cfg->num_ports++;
    }

    {
      struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&cfg->ports[cfg->num_ports].addr;
      memset(in6, 0, sizeof(*in6));
      in6->sin6_family = AF_INET6;
      in6->sin6_port = htons((uint16_t)val);
      in6->sin6_addr = in6addr_any;
      cfg->ports[cfg->num_ports].addrlen = sizeof(*in6);
      cfg->num_ports++;
    }

    return 0;
  }

  if (cfg->num_ports >= MAX_PORTS) {
    fprintf(stderr, "error: too many --port arguments (max %d)\n", MAX_PORTS);
    return -1;
  }
  if (parse_listen_addr(optarg, &cfg->ports[cfg->num_ports]) != 0) {
    fprintf(stderr, "error: invalid --port '%s'\n", optarg);
    return -1;
  }
  cfg->num_ports++;
  return 0;
}

static int handle_target_port_opt(struct config *cfg, const char *optarg)
{
  long val = atol(optarg);
  if (val < 1 || val > 65535) {
    fprintf(stderr, "error: --target-port must be 1-65535\n");
    return -1;
  }
  cfg->target_port = (uint16_t) val;
  return 0;
}

static int handle_secret_opt(struct config *cfg, const char *optarg)
{
  if (cfg->secret_file[0] != '\0') {
    fprintf(stderr, "error: --secret and --secret-file are mutually exclusive\n");
    return -1;
  }
  {
    size_t out_len = sizeof(cfg->secret);
    enum secret_encoding enc;
    if (secret_decode(optarg, cfg->secret, &out_len, &enc) != 0) {
      fprintf(stderr, "error: invalid --secret encoding\n");
      return -1;
    }
    cfg->secret_len = out_len;
  }
  return 0;
}

static int handle_secret_file_opt(struct config *cfg, const char *optarg)
{
  size_t len = strlen(optarg);
  if (len >= sizeof(cfg->secret_file)) {
    fprintf(stderr, "error: --secret-file path too long\n");
    return -1;
  }
  if (cfg->secret_len > 0) {
    fprintf(stderr, "error: --secret-file and --secret are mutually exclusive\n");
    return -1;
  }
  memcpy(cfg->secret_file, optarg, len + 1);
  return 0;
}

static int handle_timeout_opt(struct config *cfg, const char *optarg)
{
  long val = atol(optarg);
  if (val < 1 || val > 86400) {
    fprintf(stderr, "error: --timeout must be 1-86400\n");
    return -1;
  }
  cfg->timeout = (uint32_t) val;
  return 0;
}

static int handle_min_block_opt(struct config *cfg, const char *optarg)
{
  long val = atol(optarg);
  if (val < 1 || val > 86400) {
    fprintf(stderr, "error: --min-block must be 1-86400\n");
    return -1;
  }
  cfg->rate_limit.min_block = (uint32_t) val;
  return 0;
}

static int handle_max_block_opt(struct config *cfg, const char *optarg)
{
  long val = atol(optarg);
  if (val < 1 || val > 86400) {
    fprintf(stderr, "error: --max-block must be 1-86400\n");
    return -1;
  }
  cfg->rate_limit.max_block = (uint32_t) val;
  return 0;
}

static int handle_rate_limit_opt(struct config *cfg, const char *optarg)
{
  int n, w;
  if (sscanf(optarg, "%d/%d", &n, &w) != 2 || n < 1 || w < 1) {
    fprintf(stderr, "error: --rate-limit must be <fails>/<window>\n");
    return -1;
  }
  cfg->rate_limit.max_fails = n;
  cfg->rate_limit.window = w;
  return 0;
}

static int handle_interface_opt(struct config *cfg, const char *optarg)
{
  size_t len = strlen(optarg);
  if (len >= sizeof(cfg->iface)) {
    fprintf(stderr, "error: --interface name too long\n");
    return -1;
  }
  memcpy(cfg->iface, optarg, len + 1);
  return 0;
}

static int handle_user_opt(struct config *cfg, const char *optarg)
{
  size_t len = strlen(optarg);
  if (len >= sizeof(cfg->user)) {
    fprintf(stderr, "error: --user name too long\n");
    return -1;
  }
  memcpy(cfg->user, optarg, len + 1);
  return 0;
}

static int handle_group_opt(struct config *cfg, const char *optarg)
{
  size_t len = strlen(optarg);
  if (len >= sizeof(cfg->group)) {
    fprintf(stderr, "error: --group name too long\n");
    return -1;
  }
  memcpy(cfg->group, optarg, len + 1);
  return 0;
}

static int dispatch_one_opt(struct config *cfg, int opt, const char *optarg, const char *prog)
{
  static int (*const tbl[256])(struct config *, const char *) = {
    ['p'] = handle_port_opt,
    ['t'] = handle_target_port_opt,
    ['T'] = handle_timeout_opt,
    ['b'] = handle_min_block_opt,
    ['B'] = handle_max_block_opt,
    ['r'] = handle_rate_limit_opt,
    ['i'] = handle_interface_opt,
    ['u'] = handle_user_opt,
    ['g'] = handle_group_opt,
  };

  if (opt == 's')
    return handle_secret_opt(cfg, optarg);
  if (opt == 'S')
    return handle_secret_file_opt(cfg, optarg);
  if (opt == 'f') {
    cfg->foreground = 1;
    return 0;
  }
  if (opt == 'h') {
    print_usage(prog);
    exit(0);
  }
  if (tbl[(unsigned char)opt])
    return tbl[(unsigned char)opt] (cfg, optarg);
  print_usage(prog);
  return -1;
}

int parse_daemon_args(struct config *cfg, int argc, char *argv[])
{
  static const struct option long_opts[] = {
    {"port", required_argument, NULL, 'p'},
    {"target-port", required_argument, NULL, 't'},
    {"secret", required_argument, NULL, 's'},
    {"secret-file", required_argument, NULL, 'S'},
    {"timeout", required_argument, NULL, 'T'},
    {"min-block", required_argument, NULL, 'b'},
    {"max-block", required_argument, NULL, 'B'},
    {"rate-limit", required_argument, NULL, 'r'},
    {"interface", required_argument, NULL, 'i'},
    {"user", required_argument, NULL, 'u'},
    {"group", required_argument, NULL, 'g'},
    {"foreground", no_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };
  int opt;

  while ((opt = getopt_long(argc, argv, "p:t:s:S:T:b:B:r:i:u:g:fh", long_opts, NULL)) != -1) {
    if (dispatch_one_opt(cfg, opt, optarg, argv[0]) != 0)
      return -1;
  }

  if (cfg->secret_len == 0 && cfg->secret_file[0] == '\0') {
    fprintf(stderr, "error: --secret or --secret-file is required\n");
    print_usage(argv[0]);
    return -1;
  }

  if (cfg->num_ports == 0) {
    struct sockaddr_in *in4 = (struct sockaddr_in *)&cfg->ports[0].addr;
    struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)&cfg->ports[1].addr;

    memset(in4, 0, sizeof(*in4));
    in4->sin_family = AF_INET;
    in4->sin_port = htons(2222);
    in4->sin_addr.s_addr = htonl(INADDR_ANY);
    cfg->ports[0].addrlen = sizeof(*in4);

    memset(in6, 0, sizeof(*in6));
    in6->sin6_family = AF_INET6;
    in6->sin6_port = htons(2222);
    in6->sin6_addr = in6addr_any;
    cfg->ports[1].addrlen = sizeof(*in6);

    cfg->num_ports = 2;
  }

  return 0;
}
