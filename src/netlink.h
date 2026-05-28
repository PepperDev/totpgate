#ifndef NETLINK_H
#define NETLINK_H

#include <stdint.h>

int netlink_init(void);
int netlink_flush_chain(void);
int netlink_add_established_rule(void);
int netlink_add_default_drop(uint16_t port);
int netlink_rule_insert(uint32_t ip, uint16_t port, uint32_t lifetime);
void netlink_cleanup(void);

#endif
