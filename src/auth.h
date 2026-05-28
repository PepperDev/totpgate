#ifndef AUTH_H
#define AUTH_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

int auth_parse(const unsigned char *data, size_t len,
               uint32_t *token, uint16_t *port, uint32_t *lifetime);

#endif
