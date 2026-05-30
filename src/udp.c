#include "udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int udp_open(const struct sockaddr_storage *addr, socklen_t addrlen)
{
  int fd;
  int ret;
  int flags;

  fd = socket(addr->ss_family, SOCK_DGRAM, 0);
  if (fd < 0)
    return -1;

  if (addr->ss_family == AF_INET6) {
    int off = 0;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
  }

  flags = fcntl(fd, F_GETFL);
  if (flags < 0) {
    close(fd);
    return -1;
  }
  ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
  if (ret < 0) {
    close(fd);
    return -1;
  }

  ret = bind(fd, (struct sockaddr *)addr, addrlen);
  if (ret < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

int udp_recv(int fd, unsigned char *buf, size_t len, struct sockaddr_storage *src_addr, socklen_t *src_len)
{
  for (;;) {
    socklen_t addrlen = src_len ? *src_len : sizeof(struct sockaddr_storage);
    ssize_t n = recvfrom(fd, buf, len, 0, (struct sockaddr *)src_addr, &addrlen);
    if (n >= 0) {
      if (src_len)
        *src_len = addrlen;
      return (int)n;
    }
    if (errno != EINTR)
      return -1;
  }
}
