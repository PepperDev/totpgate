#ifndef NETLINK_H
#define NETLINK_H

#include <stdint.h>
#include <sys/socket.h>

int netlink_init(void);
int netlink_flush_chain(void);
int netlink_add_established_rule(const char *iface);
int netlink_add_jump_allowed(void);
int netlink_add_default_drop(uint16_t port, const char *iface);
uint64_t netlink_rule_insert(const struct sockaddr_storage *src, uint16_t port, const char *iface);
int netlink_rule_delete(uint64_t handle, uint8_t family);
void netlink_cleanup(void);

#endif
