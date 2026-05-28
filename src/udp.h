#ifndef UDP_H
#define UDP_H

#include <stddef.h>
#include <stdint.h>

int udp_open(uint16_t port);
int udp_recv(int fd, unsigned char *buf, size_t len,
             uint32_t *src_ip, uint16_t *src_port);

#endif
