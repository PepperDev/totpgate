#include "privdrop.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/prctl.h>

int drop_privileges(const char *user, const char *group, int foreground)
{
  const struct passwd *pw;
  const struct group *gr;
  uid_t uid;
  gid_t gid;

  if (getuid() != 0 && geteuid() != 0)
    return 0;

  pw = getpwnam(user);
  if (!pw) {
    if (foreground)
      fprintf(stderr, "error: drop_privileges: unknown user: %s\n", user);
    else
      syslog(LOG_ERR, "drop_privileges: unknown user: %s", user);
    return -1;
  }
  gr = getgrnam(group);
  if (!gr) {
    if (foreground)
      fprintf(stderr, "error: drop_privileges: unknown group: %s\n", group);
    else
      syslog(LOG_ERR, "drop_privileges: unknown group: %s", group);
    return -1;
  }

  uid = pw->pw_uid;
  gid = gr->gr_gid;

  if (setgroups(1, &gid) != 0) {
    if (foreground)
      fprintf(stderr, "error: drop_privileges: setgroups: %s\n", strerror(errno));
    else
      syslog(LOG_ERR, "drop_privileges: setgroups: %s", strerror(errno));
    return -1;
  }
  if (setgid(gid) != 0) {
    if (foreground)
      fprintf(stderr, "error: drop_privileges: setgid: %s\n", strerror(errno));
    else
      syslog(LOG_ERR, "drop_privileges: setgid: %s", strerror(errno));
    return -1;
  }
  if (setuid(uid) != 0) {
    if (foreground)
      fprintf(stderr, "error: drop_privileges: setuid: %s\n", strerror(errno));
    else
      syslog(LOG_ERR, "drop_privileges: setuid: %s", strerror(errno));
    return -1;
  }
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    if (foreground)
      fprintf(stderr, "error: drop_privileges: PR_SET_NO_NEW_PRIVS: %s\n", strerror(errno));
    else
      syslog(LOG_ERR, "drop_privileges: PR_SET_NO_NEW_PRIVS: %s", strerror(errno));
    return -1;
  }

  if (foreground)
    fprintf(stderr, "privileges dropped\n");
  else
    syslog(LOG_INFO, "privileges dropped");
  return 0;
}
