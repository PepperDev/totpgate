#ifndef ADDR_H
#define ADDR_H

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct {
  uint16_t family;
  uint8_t addr[16];
} ip_addr_t;

static inline void ip_from_sockaddr(const struct sockaddr_storage *ss, ip_addr_t *ip)
{
  ip->family = ss->ss_family;
  if (ss->ss_family == AF_INET) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)ss;
    memcpy(ip->addr, &in->sin_addr, 4);
    memset(ip->addr + 4, 0, 12);
  } else if (ss->ss_family == AF_INET6) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
    memcpy(ip->addr, &in6->sin6_addr, 16);
  }
}

static inline int ip_eq(const ip_addr_t *a, const ip_addr_t *b)
{
  return a->family == b->family && memcmp(a->addr, b->addr, 16) == 0;
}

static inline uint32_t ip_hash32(const ip_addr_t *ip)
{
  uint32_t h = (uint32_t) ip->family;
  uint32_t w;
  size_t i;

  for (i = 0; i < 4; i++) {
    memcpy(&w, ip->addr + i * 4, 4);
    h ^= w;
  }
  h ^= h >> 16;
  h ^= h >> 8;
  h ^= h >> 4;
  return h;
}

#endif
