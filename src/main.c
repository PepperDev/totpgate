#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/signalfd.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <fcntl.h>
#include "encode.h"
#include "privdrop.h"
#include "seccomp.h"
#include "netlink.h"
#include "parse_opts.h"
#include "udp.h"
#include "auth.h"
#include "totp.h"
#include "ratelimit.h"

#define TOTP_DIGITS 6
#define TOTP_STEP 30
#define DRIFT_BEHIND 1
#define DRIFT_AHEAD 1
#define EPOLL_MAXEVENTS 64
#define PRUNE_INTERVAL 5
#define MAX_DYNAMIC_RULES 256

struct dynamic_rule {
  uint64_t handle;
  time_t expiry;
  int active;
};

struct daemon {
  struct config *cfg;
  int udp_fds[MAX_PORTS];
  int num_udp_fds;
  int epoll_fd;
  int signal_fd;
  int maxevents;
  time_t last_prune;
  struct dynamic_rule rules[MAX_DYNAMIC_RULES];
  int num_rules;
};

static void log_msg(const struct config *cfg, int priority, const char *msg)
{
  if (cfg->foreground) {
    fprintf(stderr, "%s\n", msg);
  } else {
    syslog(priority, "%s", msg);
  }
}

int read_secret_file(const char *path, struct config *cfg)
{
  struct stat st;
  int fd;
  ssize_t n;
  char buf[4096];
  size_t len;

  if (stat(path, &st) != 0) {
    fprintf(stderr, "error: cannot stat %s: %s\n", path, strerror(errno));
    return -1;
  }

  if (st.st_mode & (S_IROTH | S_IWOTH | S_IXOTH)) {
    fprintf(stderr, "warning: %s is world-readable\n", path);
  }

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    fprintf(stderr, "error: cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  n = read(fd, buf, sizeof(buf) - 1);
  if (n < 0) {
    fprintf(stderr, "error: cannot read %s: %s\n", path, strerror(errno));
    close(fd);
    return -1;
  }
  close(fd);

  buf[n] = '\0';

  len = (size_t)n;
  while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' '))
    len--;
  buf[len] = '\0';

  {
    size_t out_len = sizeof(cfg->secret);
    enum secret_encoding enc;
    if (secret_decode(buf, cfg->secret, &out_len, &enc) != 0) {
      fprintf(stderr, "error: invalid secret encoding in %s\n", path);
      return -1;
    }
    cfg->secret_len = out_len;
  }

  return 0;
}

static void rule_track(struct daemon *d, uint64_t handle, time_t expiry)
{
  int i;
  for (i = 0; i < MAX_DYNAMIC_RULES; i++) {
    if (!d->rules[i].active) {
      d->rules[i].handle = handle;
      d->rules[i].expiry = expiry;
      d->rules[i].active = 1;
      if (i >= d->num_rules)
        d->num_rules = i + 1;
      return;
    }
  }
}

void rule_prune(struct daemon *d, time_t now)
{
  int i;
  for (i = 0; i < d->num_rules; i++) {
    if (d->rules[i].active && now >= d->rules[i].expiry) {
      netlink_rule_delete(d->rules[i].handle);
      d->rules[i].active = 0;
    }
  }
}

void daemon_cleanup(struct daemon *d);

static int daemon_setup_netlink(struct daemon *d, struct config *cfg)
{
  const char *iface;

  if (netlink_init() != 0) {
    fprintf(stderr, "error: netlink_init: %s\n", strerror(errno));
    log_msg(cfg, LOG_ERR, "netlink_init failed");
    daemon_cleanup(d);
    return -1;
  }

  if (netlink_flush_chain() != 0) {
    log_msg(cfg, LOG_WARNING, "netlink_flush_chain failed");
  }

  iface = cfg->iface[0] ? cfg->iface : NULL;

  if (netlink_add_established_rule(iface) != 0) {
    fprintf(stderr, "error: netlink_add_established_rule: %s\n", strerror(errno));
    log_msg(cfg, LOG_ERR, "netlink_add_established_rule failed");
    daemon_cleanup(d);
    return -1;
  }

  if (netlink_add_jump_allowed() != 0) {
    fprintf(stderr, "error: netlink_add_jump_allowed: %s\n", strerror(errno));
    log_msg(cfg, LOG_ERR, "netlink_add_jump_allowed failed");
    daemon_cleanup(d);
    return -1;
  }

  if (netlink_add_default_drop(cfg->target_port, iface) != 0) {
    fprintf(stderr, "error: netlink_add_default_drop: %s\n", strerror(errno));
    log_msg(cfg, LOG_ERR, "netlink_add_default_drop failed");
    daemon_cleanup(d);
    return -1;
  }

  return 0;
}

static int daemon_setup_epoll(struct daemon *d, struct config *cfg)
{
  struct epoll_event ev;
  int i;
  sigset_t mask;

  d->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (d->epoll_fd < 0) {
    fprintf(stderr, "error: epoll_create1: %s\n", strerror(errno));
    log_msg(cfg, LOG_ERR, "epoll_create1 failed");
    daemon_cleanup(d);
    return -1;
  }

  for (i = 0; i < cfg->num_ports; i++) {
    d->udp_fds[i] = udp_open(&cfg->ports[i].addr, cfg->ports[i].addrlen);
    if (d->udp_fds[i] < 0) {
      fprintf(stderr, "error: udp_open: %s\n", strerror(errno));
      log_msg(cfg, LOG_ERR, "udp_open failed");
      daemon_cleanup(d);
      return -1;
    }
    d->num_udp_fds = i + 1;

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = d->udp_fds[i];
    if (epoll_ctl(d->epoll_fd, EPOLL_CTL_ADD, d->udp_fds[i], &ev) != 0) {
      fprintf(stderr, "error: epoll_ctl ADD udp: %s\n", strerror(errno));
      log_msg(cfg, LOG_ERR, "epoll_ctl ADD udp failed");
      daemon_cleanup(d);
      return -1;
    }
  }

  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigprocmask(SIG_BLOCK, &mask, NULL);

  d->signal_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (d->signal_fd < 0) {
    fprintf(stderr, "error: signalfd: %s\n", strerror(errno));
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

int daemon_setup(struct daemon *d, struct config *cfg)
{
  int i;

  d->cfg = cfg;
  for (i = 0; i < MAX_PORTS; i++)
    d->udp_fds[i] = -1;
  d->num_udp_fds = 0;
  d->epoll_fd = -1;
  d->signal_fd = -1;
  {
    struct timespec _ts;
    clock_gettime(CLOCK_MONOTONIC, &_ts);
    d->last_prune = _ts.tv_sec;
  }
  memset(d->rules, 0, sizeof(d->rules));
  d->num_rules = 0;

  {
    struct rlimit rl;
    d->maxevents = EPOLL_MAXEVENTS;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
      if ((rlim_t) d->maxevents > rl.rlim_cur)
        d->maxevents = (int)rl.rlim_cur;
    }
  }

  if (!cfg->foreground) {
    openlog("totpgated", LOG_PID | LOG_NDELAY, LOG_DAEMON);
  }

  if (daemon_setup_netlink(d, cfg) != 0)
    return -1;

  if (daemon_setup_epoll(d, cfg) != 0)
    return -1;

  return 0;
}

static int daemon_handle_signal(struct daemon *d)
{
  struct signalfd_siginfo ssi;
  ssize_t n;

  n = read(d->signal_fd, &ssi, sizeof(ssi));
  if (n > 0) {
    char logbuf[128];

    snprintf(logbuf, sizeof(logbuf), "caught signal %u, shutting down", ssi.ssi_signo);
    log_msg(d->cfg, LOG_INFO, logbuf);
  }
  return 1;
}

static void handle_one_packet(struct daemon *d, const unsigned char *buf, int len, uint32_t src_ip, uint16_t src_port)
{
  uint32_t token;
  uint64_t rule_handle;
  char logbuf[128];
  time_t now;

  now = time(NULL);

  if (rate_limit_check(src_ip, now) != 0) {
    log_msg(d->cfg, LOG_WARNING, "rate limited, dropping");
    return;
  }

  if (auth_parse(buf, (size_t)len, &token) != 0) {
    log_msg(d->cfg, LOG_WARNING, "auth_parse failed");
    rate_limit_fail(src_ip, now, &d->cfg->rate_limit);
    return;
  }

  const struct totp_params tp = {
    .src_ip = src_ip,
    .now = now,
    .digits = TOTP_DIGITS,
    .step = TOTP_STEP,
    .drift_behind = DRIFT_BEHIND,
    .drift_ahead = DRIFT_AHEAD,
    .out_counter = NULL,
  };
  if (auth_validate(d->cfg->secret, d->cfg->secret_len, token, &tp) != 0) {
    log_msg(d->cfg, LOG_WARNING, "auth_validate failed");
    rate_limit_fail(src_ip, now, &d->cfg->rate_limit);
    return;
  }

  rate_limit_success(src_ip);

  rule_handle = netlink_rule_insert(src_ip, d->cfg->target_port, d->cfg->iface[0] ? d->cfg->iface : NULL);
  if (rule_handle == 0) {
    log_msg(d->cfg, LOG_ERR, "netlink_rule_insert failed");
    return;
  }

  rule_track(d, rule_handle, now + (time_t) d->cfg->timeout);

  snprintf(logbuf, sizeof(logbuf),
           "accepted from %u.%u.%u.%u:%u (handle %llu)",
           (src_ip >> 0) & 0xff, (src_ip >> 8) & 0xff,
           (src_ip >> 16) & 0xff, (src_ip >> 24) & 0xff, (unsigned)src_port, (unsigned long long)rule_handle);
  log_msg(d->cfg, LOG_INFO, logbuf);
}

int daemon_process(struct daemon *d)
{
  struct epoll_event events[EPOLL_MAXEVENTS];
  int nfds;
  int i;

  nfds = epoll_wait(d->epoll_fd, events, d->maxevents, 1000);
  if (nfds < 0) {
    if (errno == EINTR)
      return 0;
    return -1;
  }

  {
    struct timespec _ts;
    time_t now;

    clock_gettime(CLOCK_MONOTONIC, &_ts);
    now = time(NULL);
    if (_ts.tv_sec - d->last_prune >= PRUNE_INTERVAL) {
      d->last_prune = _ts.tv_sec;
      auth_replay_prune(now, 3600);
      rule_prune(d, now);
    }
  }

  for (i = 0; i < nfds; i++) {
    if (events[i].data.fd == d->signal_fd)
      return daemon_handle_signal(d);

    {
      int udp_fd = -1;
      int j;

      for (j = 0; j < d->num_udp_fds; j++) {
        if (events[i].data.fd == d->udp_fds[j]) {
          udp_fd = d->udp_fds[j];
          break;
        }
      }

      if (udp_fd >= 0) {
        unsigned char buf[256];
        uint32_t src_ip = 0;
        uint16_t src_port = 0;
        int ret;

        while ((ret = udp_recv(udp_fd, buf, sizeof(buf), &src_ip, &src_port)) > 0) {
          handle_one_packet(d, buf, ret, src_ip, src_port);
        }
      }
    }
  }

  return 0;
}

void daemon_cleanup(struct daemon *d)
{
  int i;

  if (d->signal_fd >= 0) {
    close(d->signal_fd);
    d->signal_fd = -1;
  }
  if (d->epoll_fd >= 0) {
    close(d->epoll_fd);
    d->epoll_fd = -1;
  }
  for (i = 0; i < d->num_udp_fds; i++) {
    if (d->udp_fds[i] >= 0) {
      close(d->udp_fds[i]);
      d->udp_fds[i] = -1;
    }
  }
  d->num_udp_fds = 0;
  memset(d->rules, 0, sizeof(d->rules));
  d->num_rules = 0;
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
  cfg.target_port = 22;
  cfg.timeout = 30;
  cfg.rate_limit.min_block = 300;
  cfg.rate_limit.max_block = 86400;
  cfg.rate_limit.max_fails = 5;
  cfg.rate_limit.window = 60;
  memcpy(cfg.user, "nobody", 7);
  memcpy(cfg.group, "nogroup", 8);

  if (parse_daemon_args(&cfg, argc, argv) != 0) {
    return 1;
  }

  if (cfg.secret_file[0] != '\0') {
    if (read_secret_file(cfg.secret_file, &cfg) != 0) {
      return 1;
    }
  }

  return daemon_run(&cfg);
}
#endif
