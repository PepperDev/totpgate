#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <syslog.h>
#include "encode.h"
#include "privdrop.h"
#include "seccomp.h"
#include "netlink.h"
#include "udp.h"
#include "auth.h"
#include "ratelimit.h"

#define TOTP_DIGITS 6
#define TOTP_STEP 30
#define DRIFT_BEHIND 1
#define DRIFT_AHEAD 1
#define EPOLL_MAXEVENTS 64
#define PRUNE_INTERVAL 5

struct config {
  uint16_t port;
  uint16_t target_port;
  unsigned char secret[256];
  size_t secret_len;
  uint32_t timeout;
  char user[32];
  char group[32];
  int foreground;
  int test_mode;
  struct rate_limit_cfg rate_limit;
};

struct daemon {
  struct config *cfg;
  int udp_fd;
  int epoll_fd;
  int signal_fd;
  time_t last_prune;
};

static void print_usage(const char *prog)
{
  fprintf(stderr,
          "Usage: %s --secret <secret> [options]\n"
          "\n"
          "Options:\n"
          "  --port <port>           UDP listen port (default: 2222)\n"
          "  --target-port <port>    TCP application port to protect (default: 22)\n"
          "  --secret <secret>       Shared secret\n"
          "                          (base32 by default; prefix with\n"
          "                           hex: or b64: for other encodings)\n"
          "  --timeout <seconds>     Rule lifetime (default: 30)\n"
          "  --min-block <seconds>   Min rate-limit block duration (default: 300)\n"
          "  --max-block <seconds>   Max rate-limit block duration (default: 86400)\n"
          "  --rate-limit <n/window> Max fails per window (default: 5/60)\n"
          "  --user <user>           Drop privileges to this user (default: nobody)\n"
          "  --group <group>         Use this group after dropping privs (default: nogroup)\n"
          "  --foreground            Log to stderr instead of syslog\n"
          "  --help                  Show this help\n", prog);
}

int parse_args(struct config *cfg, int argc, char *argv[])
{
  static const struct option long_opts[] = {
    {"port", required_argument, NULL, 'p'},
    {"target-port", required_argument, NULL, 't'},
    {"secret", required_argument, NULL, 's'},
    {"timeout", required_argument, NULL, 'T'},
    {"min-block", required_argument, NULL, 'b'},
    {"max-block", required_argument, NULL, 'B'},
    {"rate-limit", required_argument, NULL, 'r'},
    {"user", required_argument, NULL, 'u'},
    {"group", required_argument, NULL, 'g'},
    {"foreground", no_argument, NULL, 'f'},
    {"help", no_argument, NULL, 'h'},
    {NULL, 0, NULL, 0}
  };
  int opt;
  int secret_given = 0;

  while ((opt = getopt_long(argc, argv, "p:t:s:T:b:B:r:u:g:fh", long_opts, NULL)) != -1) {
    switch (opt) {
    case 'p':{
        long val = atol(optarg);
        if (val < 1 || val > 65535) {
          fprintf(stderr, "error: --port must be 1-65535\n");
          return -1;
        }
        cfg->port = (uint16_t) val;
        break;
      }
    case 't':{
        long val = atol(optarg);
        if (val < 1 || val > 65535) {
          fprintf(stderr, "error: --target-port must be 1-65535\n");
          return -1;
        }
        cfg->target_port = (uint16_t) val;
        break;
      }
    case 's':{
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
    case 'T':{
        long val = atol(optarg);
        if (val < 1 || val > 86400) {
          fprintf(stderr, "error: --timeout must be 1-86400\n");
          return -1;
        }
        cfg->timeout = (uint32_t) val;
        break;
      }
    case 'b':{
        long val = atol(optarg);
        if (val < 1 || val > 86400) {
          fprintf(stderr, "error: --min-block must be 1-86400\n");
          return -1;
        }
        cfg->rate_limit.min_block = (uint32_t) val;
        break;
      }
    case 'B':{
        long val = atol(optarg);
        if (val < 1 || val > 86400) {
          fprintf(stderr, "error: --max-block must be 1-86400\n");
          return -1;
        }
        cfg->rate_limit.max_block = (uint32_t) val;
        break;
      }
    case 'r':{
        int n = 0, w = 0;
        if (sscanf(optarg, "%d/%d", &n, &w) != 2 || n < 1 || w < 1) {
          fprintf(stderr, "error: --rate-limit must be <fails>/<window>\n");
          return -1;
        }
        cfg->rate_limit.max_fails = (uint32_t) n;
        cfg->rate_limit.window = (uint32_t) w;
        break;
      }
    case 'u':{
        size_t len = strlen(optarg);
        if (len >= sizeof(cfg->user)) {
          fprintf(stderr, "error: --user too long\n");
          return -1;
        }
        memcpy(cfg->user, optarg, len + 1);
        break;
      }
    case 'g':{
        size_t len = strlen(optarg);
        if (len >= sizeof(cfg->group)) {
          fprintf(stderr, "error: --group too long\n");
          return -1;
        }
        memcpy(cfg->group, optarg, len + 1);
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

static void log_msg(struct config *cfg, int priority, const char *msg)
{
  if (cfg->foreground) {
    fprintf(stderr, "%s\n", msg);
  } else {
    syslog(priority, "%s", msg);
  }
}

void daemon_cleanup(struct daemon *d);

int daemon_setup(struct daemon *d, struct config *cfg)
{
  struct epoll_event ev;
  sigset_t mask;

  d->cfg = cfg;
  d->udp_fd = -1;
  d->epoll_fd = -1;
  d->signal_fd = -1;
  d->last_prune = 0;

  if (!cfg->foreground) {
    openlog("totpgated", LOG_PID | LOG_NDELAY, LOG_DAEMON);
  }

  if (netlink_init() != 0) {
    log_msg(cfg, LOG_ERR, "netlink_init failed");
    return -1;
  }

  if (netlink_flush_chain() != 0) {
    log_msg(cfg, LOG_WARNING, "netlink_flush_chain failed");
  }

  if (netlink_add_established_rule() != 0) {
    log_msg(cfg, LOG_ERR, "netlink_add_established_rule failed");
    daemon_cleanup(d);
    return -1;
  }

  if (netlink_add_default_drop(cfg->target_port) != 0) {
    log_msg(cfg, LOG_ERR, "netlink_add_default_drop failed");
    daemon_cleanup(d);
    return -1;
  }

  d->udp_fd = udp_open(cfg->port);
  if (d->udp_fd < 0) {
    log_msg(cfg, LOG_ERR, "udp_open failed");
    daemon_cleanup(d);
    return -1;
  }

  d->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (d->epoll_fd < 0) {
    log_msg(cfg, LOG_ERR, "epoll_create1 failed");
    daemon_cleanup(d);
    return -1;
  }

  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN | EPOLLET;
  ev.data.fd = d->udp_fd;
  if (epoll_ctl(d->epoll_fd, EPOLL_CTL_ADD, d->udp_fd, &ev) != 0) {
    log_msg(cfg, LOG_ERR, "epoll_ctl ADD udp failed");
    daemon_cleanup(d);
    return -1;
  }

  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, NULL);

  d->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (d->signal_fd < 0) {
    log_msg(cfg, LOG_ERR, "signalfd failed");
    daemon_cleanup(d);
    return -1;
  }

  memset(&ev, 0, sizeof(ev));
  ev.events = EPOLLIN;
  ev.data.fd = d->signal_fd;
  if (epoll_ctl(d->epoll_fd, EPOLL_CTL_ADD, d->signal_fd, &ev) != 0) {
    log_msg(cfg, LOG_ERR, "epoll_ctl ADD signalfd failed");
    daemon_cleanup(d);
    return -1;
  }

  return 0;
}

int daemon_process(struct daemon *d)
{
  struct epoll_event events[EPOLL_MAXEVENTS];
  int nfds;
  int i;
  time_t now;
  char logbuf[128];

  nfds = epoll_wait(d->epoll_fd, events, EPOLL_MAXEVENTS, 1000);
  if (nfds < 0) {
    if (errno == EINTR)
      return 0;
    return -1;
  }

  now = time(NULL);

  if (now - d->last_prune >= PRUNE_INTERVAL) {
    auth_replay_prune(now, 3600);
    d->last_prune = now;
  }

  for (i = 0; i < nfds; i++) {
    if (events[i].data.fd == d->signal_fd) {
      struct signalfd_siginfo ssi;
      ssize_t n;

      n = read(d->signal_fd, &ssi, sizeof(ssi));
      if (n > 0) {
        snprintf(logbuf, sizeof(logbuf), "caught signal %u, shutting down", ssi.ssi_signo);
        log_msg(d->cfg, LOG_INFO, logbuf);
      }
      return 1;
    }

    if (events[i].data.fd == d->udp_fd) {
      unsigned char buf[256];
      uint32_t src_ip;
      uint16_t src_port;
      int ret;
      uint32_t token;
      uint16_t token_port;
      uint32_t lifetime;
      uint16_t target_port;
      uint64_t rule_handle;

      while ((ret = udp_recv(d->udp_fd, buf, sizeof(buf), &src_ip, &src_port)) > 0) {
        token = 0;
        token_port = 0;
        lifetime = 0;

        if (rate_limit_check(src_ip, now) != 0) {
          log_msg(d->cfg, LOG_WARNING, "rate limited, dropping");
          continue;
        }

        if (auth_parse(buf, (size_t)ret, &token, &token_port, &lifetime) != 0) {
          log_msg(d->cfg, LOG_WARNING, "auth_parse failed");
          rate_limit_fail(src_ip, now, &d->cfg->rate_limit);
          continue;
        }

        if (auth_validate(d->cfg->secret, d->cfg->secret_len,
                          token, src_ip, now, TOTP_DIGITS, TOTP_STEP, DRIFT_BEHIND, DRIFT_AHEAD) != 0) {
          log_msg(d->cfg, LOG_WARNING, "auth_validate failed");
          rate_limit_fail(src_ip, now, &d->cfg->rate_limit);
          continue;
        }

        rate_limit_success(src_ip);

        target_port = token_port ? token_port : d->cfg->target_port;

        rule_handle = netlink_rule_insert(src_ip, target_port);
        if (rule_handle == 0) {
          log_msg(d->cfg, LOG_ERR, "netlink_rule_insert failed");
          continue;
        }

        snprintf(logbuf, sizeof(logbuf),
                 "accepted from %u.%u.%u.%u:%u (handle %llu)",
                 (src_ip >> 0) & 0xff,
                 (src_ip >> 8) & 0xff,
                 (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff, (unsigned)src_port, (unsigned long long)rule_handle);
        log_msg(d->cfg, LOG_INFO, logbuf);
      }
    }
  }

  return 0;
}

void daemon_cleanup(struct daemon *d)
{
  if (d->signal_fd >= 0) {
    close(d->signal_fd);
    d->signal_fd = -1;
  }
  if (d->epoll_fd >= 0) {
    close(d->epoll_fd);
    d->epoll_fd = -1;
  }
  if (d->udp_fd >= 0) {
    close(d->udp_fd);
    d->udp_fd = -1;
  }
  netlink_cleanup();
  if (!d->cfg->foreground) {
    closelog();
  }
}

int daemon_run(struct config *cfg)
{
  struct daemon d;

  if (daemon_setup(&d, cfg) != 0) {
    return 1;
  }

  if (drop_privileges(cfg->user, cfg->group, cfg->foreground) != 0) {
    daemon_cleanup(&d);
    return 1;
  }

  install_seccomp(cfg->foreground);

  while (daemon_process(&d) == 0) {
    if (cfg->test_mode)
      break;
  }

  daemon_cleanup(&d);
  return 0;
}

#ifndef DAEMON_CORE_ONLY
int main(int argc, char *argv[])
{
  struct config cfg;

  memset(&cfg, 0, sizeof(cfg));
  cfg.port = 2222;
  cfg.target_port = 22;
  cfg.timeout = 30;
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
  memcpy(cfg.user, "nobody", 7);
  memcpy(cfg.group, "nogroup", 8);

  if (parse_args(&cfg, argc, argv) != 0) {
    return 1;
  }

  return daemon_run(&cfg);
}
#endif
