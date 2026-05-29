#include "netlink.h"
#include <stdint.h>
#include <string.h>

int g_nl_init_ret;
int g_nl_flush_ret;
int g_nl_est_ret;
int g_nl_drop_ret;
uint16_t g_nl_drop_port;
char g_nl_drop_iface[16];
int g_nl_insert_ret;
uint32_t g_nl_insert_ip;
uint16_t g_nl_insert_port;
char g_nl_insert_iface[16];
uint64_t g_nl_insert_return;
int g_nl_del_ret;
uint64_t g_nl_del_handle;
int g_nl_cleanup_called;

void mock_netlink_reset(void)
{
  g_nl_init_ret = 0;
  g_nl_flush_ret = 0;
  g_nl_est_ret = 0;
  g_nl_drop_ret = 0;
  g_nl_drop_port = 0;
  g_nl_drop_iface[0] = '\0';
  g_nl_insert_ret = 0;
  g_nl_insert_ip = 0;
  g_nl_insert_port = 0;
  g_nl_insert_iface[0] = '\0';
  g_nl_insert_return = 1;
  g_nl_del_ret = 0;
  g_nl_del_handle = 0;
  g_nl_cleanup_called = 0;
}

int netlink_init(void)
{
  return g_nl_init_ret;
}

int netlink_flush_chain(void)
{
  return g_nl_flush_ret;
}

int netlink_add_established_rule(const char *iface)
{
  (void)iface;
  return g_nl_est_ret;
}

int netlink_add_default_drop(uint16_t port, const char *iface)
{
  g_nl_drop_port = port;
  if (iface) {
    size_t len = strlen(iface);
    if (len >= sizeof(g_nl_drop_iface))
      len = sizeof(g_nl_drop_iface) - 1;
    memcpy(g_nl_drop_iface, iface, len);
    g_nl_drop_iface[len] = '\0';
  } else {
    g_nl_drop_iface[0] = '\0';
  }
  return g_nl_drop_ret;
}

int netlink_add_jump_allowed(void)
{
  return 0;
}

uint64_t netlink_rule_insert(uint32_t ip, uint16_t port, const char *iface)
{
  g_nl_insert_ip = ip;
  g_nl_insert_port = port;
  if (iface) {
    size_t len = strlen(iface);
    if (len >= sizeof(g_nl_insert_iface))
      len = sizeof(g_nl_insert_iface) - 1;
    memcpy(g_nl_insert_iface, iface, len);
    g_nl_insert_iface[len] = '\0';
  } else {
    g_nl_insert_iface[0] = '\0';
  }
  return g_nl_insert_return;
}

int netlink_rule_delete(uint64_t handle)
{
  g_nl_del_handle = handle;
  return g_nl_del_ret;
}

void netlink_cleanup(void)
{
  g_nl_cleanup_called = 1;
}
