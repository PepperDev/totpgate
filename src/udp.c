#include "udp.h"

int udp_open(uint16_t port)
{
    (void)port;
    return -1;
}

int udp_recv(int fd, unsigned char *buf, size_t len,
             uint32_t *src_ip, uint16_t *src_port)
{
    (void)fd;
    (void)buf;
    (void)len;
    (void)src_ip;
    (void)src_port;
    return -1;
}
