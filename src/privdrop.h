#ifndef PRIVDROP_H
#define PRIVDROP_H

int drop_privileges(const char *user, const char *group, int foreground);

#endif
