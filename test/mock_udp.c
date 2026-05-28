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
  g_last_fd = -1;
}

int udp_open(uint16_t port)
{
  struct sockaddr_in addr;

  g_udp_open_port = port;
  if (g_udp_open_ret < 0) {
    return -1;
  }
  g_last_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (g_last_fd < 0) {
    return -1;
  }
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);
  bind(g_last_fd, (struct sockaddr *)&addr, sizeof(addr));
  g_udp_open_ret = g_last_fd;
  return g_last_fd;
}

int udp_recv(int fd, unsigned char *buf, size_t len, uint32_t *src_ip, uint16_t *src_port)
{
  size_t copy_len;

  (void)fd;
  if (g_udp_recv_done) {
    return -1;
  }
  g_udp_recv_done = 1;
  if (g_udp_recv_len > 0) {
    copy_len = (g_udp_recv_len < len) ? g_udp_recv_len : len;
    memcpy(buf, g_udp_recv_buf, copy_len);
    if (src_ip) {
      *src_ip = g_udp_recv_src_ip;
    }
    if (src_port) {
      *src_port = g_udp_recv_src_port;
    }
    return (int)copy_len;
  }
  return g_udp_recv_ret;
}
