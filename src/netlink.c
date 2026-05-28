#include "netlink.h"

int netlink_init(void)
{
    return -1;
}

int netlink_flush_chain(void)
{
    return -1;
}

int netlink_add_established_rule(void)
{
    return -1;
}

int netlink_add_default_drop(uint16_t port)
{
    (void)port;
    return -1;
}

int netlink_rule_insert(uint32_t ip, uint16_t port, uint32_t lifetime)
{
    (void)ip;
    (void)port;
    (void)lifetime;
    return -1;
}

void netlink_cleanup(void)
{
}
