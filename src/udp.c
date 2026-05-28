#include "udp.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int udp_open(uint16_t port)
{
  int fd;
  int ret;
  int flags;
  struct sockaddr_in addr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
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

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
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
