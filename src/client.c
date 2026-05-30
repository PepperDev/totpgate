#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "client.h"
#include "encode.h"
#include "totp.h"

#define TOTP_DIGITS 6
#define TOTP_STEP 30

static void print_usage(const char *prog)
{
  fprintf(stderr,
          "Usage: %s --secret <secret> [options] <server>[:<port>]\n"
          "\n"
          "Options:\n"
          "  --port <port>           UDP port (default: 2222)\n"
          "                          Ignored when <server> includes a port\n"
          "  --secret <secret>       Shared secret\n"
          "                          (base32 by default; prefix with\n"
          "                           hex: or b64: for other encodings)\n"
          "  --help                  Show this help\n", prog);
}

static int parse_host_port(const char *str, uint16_t *port, size_t *host_len)
{
  const char *port_start;

  if (str[0] == '[') {
    const char *close = strchr(str, ']');
    if (!close)
      return 0;
    if (close[1] != ':')
      return 0;
    port_start = close + 2;
    *host_len = (size_t)(close - str - 1);
  } else {
    const char *colon = strrchr(str, ':');
    if (colon == NULL)
      return 0;
    /* If there are multiple colons, it's a bare IPv6 address (no port). */
    if (memchr(str, ':', (size_t)(colon - str)) != NULL)
      return 0;
    port_start = colon + 1;
    *host_len = (size_t)(colon - str);
  }

  {
    char *end;
    long val;

    val = strtol(port_start, &end, 10);
    if (*end == '\0' && val >= 1 && val <= 65535) {
      *port = (uint16_t) val;
      return 1;
    }
  }
  return 0;
}

static int handle_port_opt(struct client_cfg *cfg, const char *optarg)
{
  long val = atol(optarg);

  if (val < 1 || val > 65535) {
    fprintf(stderr, "error: --port must be 1-65535\n");
    return -1;
  }
  cfg->port = (uint16_t) val;
  return 0;
}

static int handle_secret_opt(struct client_cfg *cfg, const char *optarg)
{
  size_t out_len = sizeof(cfg->secret);
  enum secret_encoding enc;

  if (secret_decode(optarg, cfg->secret, &out_len, &enc) != 0) {
    fprintf(stderr, "error: invalid --secret encoding\n");
    return -1;
  }
  cfg->secret_len = out_len;
  return 0;
}

static int parse_server_arg(struct client_cfg *cfg, const char *src)
{
  const char *host_start = src;
  size_t slen = strlen(src);

  {
    uint16_t p;
    size_t host_len;

    if (parse_host_port(src, &p, &host_len)) {
      cfg->port = p;
      /* Bracketed [IPv6]:port strips the brackets — skip the '[' */
      if (src[0] == '[')
        host_start = src + 1;
      slen = host_len;
    }
  }

  if (slen >= sizeof(cfg->server)) {
    fprintf(stderr, "error: server name too long\n");
    return -1;
  }
  memcpy(cfg->server, host_start, slen);
  cfg->server[slen] = '\0';
  return 0;
}

int parse_args(struct client_cfg *cfg, int argc, char *argv[])
{
  static const struct option long_opts[] = {
    {"port", required_argument, NULL, 'p'},
    {"secret", required_argument, NULL, 's'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };
  int opt;
  int secret_given = 0;

  memset(cfg, 0, sizeof(*cfg));
  cfg->port = 2222;

  while ((opt = getopt_long(argc, argv, "p:s:h", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'p':
      if (handle_port_opt(cfg, optarg) != 0)
        return -1;
      break;
    case 's':
      if (handle_secret_opt(cfg, optarg) != 0)
        return -1;
      secret_given = 1;
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

  if (optind >= argc) {
    fprintf(stderr, "error: <server> argument is required\n");
    print_usage(argv[0]);
    return -1;
  }

  if (parse_server_arg(cfg, argv[optind]) != 0)
    return -1;
  optind++;

  return 0;
}

int client_run(struct client_cfg *cfg)
{
  char pkt[64];
  size_t pkt_len;
  uint32_t token;
  struct addrinfo hints;
  struct addrinfo *ai;
  int ret;
  int fd;
  uint16_t port;
  char host[INET6_ADDRSTRLEN];
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
  } sa;

  token = totp_generate(cfg->secret, cfg->secret_len, (uint64_t) (time(NULL) / TOTP_STEP), TOTP_DIGITS);
  pkt_len = (size_t)snprintf(pkt, sizeof(pkt), "%06u", (unsigned)token);

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  ret = getaddrinfo(cfg->server, NULL, &hints, &ai);
  if (ret != 0) {
    fprintf(stderr, "error: resolve %s: %s\n", cfg->server, gai_strerror(ret));
    return -1;
  }

  if (ai == NULL) {
    fprintf(stderr, "error: no address for %s\n", cfg->server);
    return -1;
  }

  port = cfg->port;
  memset(&sa, 0, sizeof(sa));

  if (ai->ai_family == AF_INET6) {
    const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ai->ai_addr;
    sa.sin6.sin6_family = AF_INET6;
    sa.sin6.sin6_port = htons(port);
    sa.sin6.sin6_addr = s6->sin6_addr;
    inet_ntop(AF_INET6, &s6->sin6_addr, host, sizeof(host));
  } else {
    const struct sockaddr_in *s4 = (const struct sockaddr_in *)ai->ai_addr;
    sa.sin.sin_family = AF_INET;
    sa.sin.sin_port = htons(port);
    sa.sin.sin_addr = s4->sin_addr;
    inet_ntop(AF_INET, &s4->sin_addr, host, sizeof(host));
  }

  fd = socket(ai->ai_family, SOCK_DGRAM, 0);
  if (fd < 0) {
    fprintf(stderr, "error: socket: %s\n", strerror(errno));
    freeaddrinfo(ai);
    return -1;
  }

  ret = sendto(fd, pkt, pkt_len, 0, (const struct sockaddr *)&sa, ai->ai_addrlen);
  if (ret < 0) {
    fprintf(stderr, "error: sendto %s:%u: %s\n", host, (unsigned)port, strerror(errno));
    close(fd);
    freeaddrinfo(ai);
    return -1;
  }

  printf("sent %zu bytes to %s:%u\n", pkt_len, host, (unsigned)port);

  close(fd);
  freeaddrinfo(ai);
  return 0;
}

#ifndef CLIENT_CORE_ONLY
int main(int argc, char *argv[])
{
  struct client_cfg cfg;

  if (parse_args(&cfg, argc, argv) != 0) {
    return 1;
  }

  return client_run(&cfg) != 0 ? 1 : 0;
}
#endif
