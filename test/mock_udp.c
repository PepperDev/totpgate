#include "udp.h"
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>

int g_udp_open_ret;
uint16_t g_udp_open_port;
int g_udp_recv_ret;
unsigned char g_udp_recv_buf[256];
size_t g_udp_recv_len;
uint32_t g_udp_recv_src_ip;
uint16_t g_udp_recv_src_port;
int g_udp_recv_done;
int g_udp_recv_family;
int g_udp_recv_ipv4_mapped;

static int g_last_fd;

void mock_udp_reset(void)
{
  if (g_last_fd >= 0) {
    close(g_last_fd);
  }
  g_udp_open_ret = 0;
  g_udp_open_port = 0;
  g_udp_recv_ret = -1;
  g_udp_recv_len = 0;
  g_udp_recv_src_ip = 0;
  g_udp_recv_src_port = 0;
  g_udp_recv_done = 0;
  g_udp_recv_family = AF_INET;
  g_udp_recv_ipv4_mapped = 0;
  g_last_fd = -1;
}

static uint16_t get_port_from_addr(const struct sockaddr_storage *addr)
{
  if (addr->ss_family == AF_INET) {
    const struct sockaddr_in *in = (const struct sockaddr_in *)addr;
    return ntohs(in->sin_port);
  }
  if (addr->ss_family == AF_INET6) {
    const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)addr;
    return ntohs(in6->sin6_port);
  }
  return 0;
}

int udp_open(const struct sockaddr_storage *addr, socklen_t addrlen)
{
  (void)addrlen;
  if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6) {
    g_udp_open_port = 0;
    if (g_udp_open_ret < 0)
      return -1;
    g_last_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (g_last_fd < 0)
      return -1;
    g_udp_open_ret = g_last_fd;
    return g_last_fd;
  }

  g_udp_open_port = get_port_from_addr(addr);

  if (g_udp_open_ret < 0)
    return -1;

  g_last_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (g_last_fd < 0)
    return -1;

  {
    int yes = 1;
    setsockopt(g_last_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
  }
  if (bind(g_last_fd, (struct sockaddr *)addr, addrlen) != 0) {
    close(g_last_fd);
    g_last_fd = -1;
    return -1;
  }
  g_udp_open_ret = g_last_fd;
  return g_last_fd;
}

int udp_recv(int fd, unsigned char *buf, size_t len, struct sockaddr_storage *src_addr, socklen_t *src_len)
{
  (void)fd;
  (void)src_len;
  if (g_udp_recv_done) {
    return -1;
  }
  g_udp_recv_done = 1;
  if (g_udp_recv_len > 0) {
    size_t copy_len = (g_udp_recv_len < len) ? g_udp_recv_len : len;
    memcpy(buf, g_udp_recv_buf, copy_len);
    if (src_addr) {
      if (g_udp_recv_family == AF_INET6) {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)src_addr;
        memset(in6, 0, sizeof(*in6));
        in6->sin6_family = AF_INET6;
        if (g_udp_recv_ipv4_mapped) {
          in6->sin6_addr.s6_addr[10] = 0xff;
          in6->sin6_addr.s6_addr[11] = 0xff;
          memcpy(&in6->sin6_addr.s6_addr[12], &g_udp_recv_src_ip, 4);
        } else {
          memcpy(&in6->sin6_addr, &g_udp_recv_src_ip, 4);
        }
        in6->sin6_port = htons(g_udp_recv_src_port);
      } else {
        struct sockaddr_in *in = (struct sockaddr_in *)src_addr;
        memset(in, 0, sizeof(*in));
        in->sin_family = AF_INET;
        in->sin_addr.s_addr = g_udp_recv_src_ip;
        in->sin_port = htons(g_udp_recv_src_port);
      }
    }
    return (int)copy_len;
  }
  return g_udp_recv_ret;
}
