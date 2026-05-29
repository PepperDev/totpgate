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

int udp_recv(int fd, unsigned char *buf, size_t len, uint32_t *src_ip, uint16_t *src_port)
{
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  ssize_t n;

  for (;;) {
    n = recvfrom(fd, buf, len, 0, (struct sockaddr *)&addr, &addrlen);
    if (n >= 0) {
      if (src_ip)
        *src_ip = addr.sin_addr.s_addr;
      if (src_port)
        *src_port = addr.sin_port;
      return (int)n;
    }
    if (errno == EINTR)
      continue;
    return -1;
  }
}
