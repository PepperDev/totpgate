#ifndef NETLINK_H
#define NETLINK_H

#include <stdint.h>

int netlink_init(void);
int netlink_flush_chain(void);
int netlink_add_established_rule(void);
int netlink_add_default_drop(uint16_t port);
uint64_t netlink_rule_insert(uint32_t ip, uint16_t port);
int netlink_rule_delete(uint64_t handle);
void netlink_cleanup(void);

#endif
