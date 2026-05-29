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

  /* PR_SET_NO_NEW_PRIVS works without privilege — always try so that
     seccomp can install even under capability-based execution. */
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    log_msg(foreground, LOG_WARNING, "warning: PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
  }

  log_msg(foreground, LOG_INFO, "privileges dropped");
  return 0;
}
