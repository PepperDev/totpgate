#include "privdrop.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/capability.h>

static void log_msg(int foreground, int level, const char *fmt, ...)
{
  va_list ap;
  char msg[256];

  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);

  if (foreground)
    fprintf(stderr, "%s\n", msg);
  else
    syslog(level, "%s", msg);
}

int drop_privileges(const char *user, const char *group, int foreground)
{
  const struct passwd *pw;
  const struct group *gr;
  uid_t uid;
  gid_t gid;

  pw = getpwnam(user);
  if (!pw) {
    log_msg(foreground, LOG_ERR, "error: drop_privileges: unknown user: %s", user);
    return -1;
  }
  gr = getgrnam(group);
  if (!gr) {
    log_msg(foreground, LOG_ERR, "error: drop_privileges: unknown group: %s", group);
    return -1;
  }

  uid = pw->pw_uid;
  gid = gr->gr_gid;

  /* Preserve capabilities across setuid so we can keep CAP_NET_ADMIN
     for netlink (firewall) operations. */
  if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
    log_msg(foreground, LOG_WARNING, "warning: PR_SET_KEEPCAPS: %s", strerror(errno));
  }

  /* Try to drop privileges.  Operations that fail with EPERM are fine —
     we may already be running unprivileged (e.g. under file capabilities). */

  if (setgroups(1, &gid) != 0) {
    if (errno != EPERM) {
      log_msg(foreground, LOG_ERR, "error: drop_privileges: setgroups: %s", strerror(errno));
      return -1;
    }
  }
  if (setgid(gid) != 0) {
    if (errno != EPERM) {
      log_msg(foreground, LOG_ERR, "error: drop_privileges: setgid: %s", strerror(errno));
      return -1;
    }
  }
  if (setuid(uid) != 0) {
    if (errno != EPERM) {
      log_msg(foreground, LOG_ERR, "error: drop_privileges: setuid: %s", strerror(errno));
      return -1;
    }
  }

  /* Re-enable CAP_NET_ADMIN in the effective set; after setuid()
     the kernel clears effective capabilities even with KEEPCAPS. */
  {
    struct __user_cap_header_struct cap_hdr = {
      .version = _LINUX_CAPABILITY_VERSION_3,
      .pid = 0,
    };
    struct __user_cap_data_struct cap_data[2] = { {0} };

    if (syscall(SYS_capget, &cap_hdr, &cap_data) == 0) {
      cap_data[0].effective = (1 << CAP_NET_ADMIN);
      cap_data[0].permitted = (1 << CAP_NET_ADMIN);
      cap_data[0].inheritable = 0;
      cap_data[1].effective = 0;
      cap_data[1].permitted = 0;
      cap_data[1].inheritable = 0;
      if (syscall(SYS_capset, &cap_hdr, &cap_data) != 0)
        log_msg(foreground, LOG_WARNING, "warning: capset: %s", strerror(errno));
    } else {
      log_msg(foreground, LOG_WARNING, "warning: capget: %s", strerror(errno));
    }
  }

  /* PR_SET_NO_NEW_PRIVS works without privilege — always try so that
     seccomp can install even under capability-based execution. */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    log_msg(foreground, LOG_WARNING, "warning: PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
  }

  log_msg(foreground, LOG_INFO, "privileges dropped");
  return 0;
}
