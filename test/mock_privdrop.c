#include "privdrop.h"

int drop_privileges(const char *user, const char *group, int foreground)
{
  (void)user;
  (void)group;
  (void)foreground;
  return 0;
}
