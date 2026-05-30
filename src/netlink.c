#include "netlink.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#ifndef NFT_BITWISE_MASK_XOR
#define NFT_BITWISE_MASK_XOR 0
#endif

#define TABLE_NAME    "totpgate"
#define CHAIN_NAME    "input"
#define ALLOWED_NAME  "allowed_ips"
#define BUF_SIZE      4096

static int g_fd = -1;
static uint32_t g_seq;
static uint32_t g_portid;
static uint64_t g_next_handle;

/* helpers for raw byte-order conversion without <arpa/inet.h> */

static uint16_t bs16(uint16_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return (uint16_t) ((x << 8) | (x >> 8));
#else
  return x;
#endif
}

static uint32_t bs32(uint32_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return ((x << 24) | ((x & 0xff00) << 8)
          | ((x >> 8) & 0xff00) | (x >> 24));
#else
  return x;
#endif
}

static uint64_t bs64(uint64_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return ((uint64_t) bs32((uint32_t) x) << 32) | bs32((uint32_t) (x >> 32));
#else
  return x;
#endif
}

/* ---- netlink message helpers ---- */

static struct nlmsghdr *msg_start(char *buf)
{
  struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

  memset(nlh, 0, sizeof(*nlh));
  nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
  nlh->nlmsg_seq = ++g_seq;
  nlh->nlmsg_pid = g_portid;
  return nlh;
}

static struct nfgenmsg *msg_nfg(struct nlmsghdr *nlh)
{
  return (struct nfgenmsg *)NLMSG_DATA(nlh);
}

static void msg_set(struct nlmsghdr *nlh, uint16_t type, uint16_t flags, uint8_t family)
{
  struct nfgenmsg *nfg = msg_nfg(nlh);

  nlh->nlmsg_type = (uint16_t) ((NFNL_SUBSYS_NFTABLES << 8) | type);
  nlh->nlmsg_flags = flags;
  nfg->nfgen_family = family;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = 0;
}

static struct nlattr *put_attr(struct nlmsghdr *nlh, uint16_t type, uint16_t plen, const void *data)
{
  uint16_t total = NLA_HDRLEN + plen;
  int pad = (int)NLA_ALIGN(total) - (int)total;
  struct nlattr *nla;

  nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
  nla->nla_len = total;
  nla->nla_type = type;
  if (data && plen > 0) {
    memcpy((char *)nla + NLA_HDRLEN, data, plen);
  }
  nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(total);
  if (pad > 0) {
    memset((char *)nlh + nlh->nlmsg_len - pad, 0, (size_t)pad);
  }
  return nla;
}

static struct nlattr *begin_nest(struct nlmsghdr *nlh, uint16_t type)
{
  struct nlattr *nla;

  nla = (struct nlattr *)((char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len));
  nla->nla_len = 0;
  nla->nla_type = type | NLA_F_NESTED;
  nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_HDRLEN;
  return nla;
}

static void end_nest(struct nlmsghdr *nlh, struct nlattr *nla)
{
  nla->nla_len = (uint16_t) ((char *)nlh + nlh->nlmsg_len - (char *)nla);
}

/* convenience: put a NUL-terminated string attribute */
static void put_str(struct nlmsghdr *nlh, uint16_t type, const char *s)
{
  put_attr(nlh, type, (uint16_t) (strlen(s) + 1), s);
}

/* put uint32 attribute in big-endian (network byte order) */
static void put_be32(struct nlmsghdr *nlh, uint16_t type, uint32_t val)
{
  uint32_t be = bs32(val);

  put_attr(nlh, type, 4, &be);
}

/* put uint64 attribute in big-endian (network byte order) */
static void put_be64(struct nlmsghdr *nlh, uint16_t type, uint64_t val)
{
  uint64_t be = bs64(val);

  put_attr(nlh, type, 8, &be);
}

/* ---- expression builders (append to the rule's NFTA_RULE_EXPRESSIONS) ---- */

static void add_expr_immediate_verdict(struct nlmsghdr *nlh, uint32_t verdict)
{
  struct nlattr *expr, *data, *vd;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "immediate");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
  vd = begin_nest(nlh, NFTA_IMMEDIATE_DATA);
  {
    struct nlattr *vd2 = begin_nest(nlh, NFTA_DATA_VERDICT);

    put_be32(nlh, NFTA_VERDICT_CODE, verdict);
    end_nest(nlh, vd2);
  }
  end_nest(nlh, vd);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

static void add_expr_immediate_verdict_chain(struct nlmsghdr *nlh, uint32_t verdict, const char *chain)
{
  struct nlattr *expr, *data, *vd;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "immediate");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
  vd = begin_nest(nlh, NFTA_IMMEDIATE_DATA);
  {
    struct nlattr *vd2 = begin_nest(nlh, NFTA_DATA_VERDICT);

    put_be32(nlh, NFTA_VERDICT_CODE, verdict);
    put_str(nlh, NFTA_VERDICT_CHAIN, chain);
    end_nest(nlh, vd2);
  }
  end_nest(nlh, vd);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

static void add_expr_payload_load(struct nlmsghdr *nlh, uint32_t base, uint32_t offset, uint32_t len, uint32_t dreg)
{
  struct nlattr *expr, *data;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "payload");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_PAYLOAD_DREG, dreg);
  put_be32(nlh, NFTA_PAYLOAD_BASE, base);
  put_be32(nlh, NFTA_PAYLOAD_OFFSET, offset);
  put_be32(nlh, NFTA_PAYLOAD_LEN, len);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

static void add_expr_cmp(struct nlmsghdr *nlh, uint32_t sreg, uint32_t op, const void *data, uint32_t dlen)
{
  struct nlattr *expr, *edata, *vd;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "cmp");
  edata = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_CMP_SREG, sreg);
  put_be32(nlh, NFTA_CMP_OP, op);
  vd = begin_nest(nlh, NFTA_CMP_DATA);
  put_attr(nlh, NFTA_DATA_VALUE, dlen, data);
  end_nest(nlh, vd);
  end_nest(nlh, edata);
  end_nest(nlh, expr);
}

static void add_expr_meta_l4proto(struct nlmsghdr *nlh, uint32_t dreg)
{
  struct nlattr *expr, *data;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "meta");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_META_DREG, dreg);
  put_be32(nlh, NFTA_META_KEY, NFT_META_L4PROTO);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

static void add_expr_meta_iifname(struct nlmsghdr *nlh, uint32_t dreg)
{
  struct nlattr *expr, *data;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "meta");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_META_DREG, dreg);
  put_be32(nlh, NFTA_META_KEY, NFT_META_IIFNAME);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

static void add_expr_ct_state(struct nlmsghdr *nlh, uint32_t dreg)
{
  struct nlattr *expr, *data;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "ct");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_CT_DREG, dreg);
  put_be32(nlh, NFTA_CT_KEY, NFT_CT_STATE);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

struct bitwise_regs {
  uint32_t sreg;
  uint32_t dreg;
};

static int handle_nlmsg_error(const struct nlmsghdr *nlh)
{
  if (nlh->nlmsg_type != NLMSG_ERROR)
    return 0;
  if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
    errno = EBADMSG;
    return -1;
  }
  {
    const struct nlmsgerr *er = (const struct nlmsgerr *)NLMSG_DATA(nlh);
    int e;

    if (er->error < 0)
      e = -er->error;
    else
      e = er->error;
    if (e != 0) {
      errno = e;
      return -1;
    }
  }
  return 0;
}

static int process_batch_replies(void)
{
  for (;;) {
    struct pollfd pfd;

    pfd.fd = g_fd;
    pfd.events = POLLIN;
    if (poll(&pfd, 1, 100) <= 0)
      break;

    {
      char reply[BUF_SIZE];
      ssize_t n = recv(g_fd, reply, sizeof(reply), 0);

      if (n < 0) {
        if (errno == EINTR)
          continue;
        break;
      }
      if ((size_t)n < sizeof(struct nlmsghdr))
        continue;

      {
        struct nlmsghdr *nlh = (struct nlmsghdr *)reply;
        int remaining = (int)n;

        while (NLMSG_OK(nlh, remaining)) {
          if (handle_nlmsg_error(nlh) != 0)
            return -1;
          nlh = NLMSG_NEXT(nlh, remaining);
        }
      }
    }
  }
  return 0;
}

static void add_expr_bitwise(struct nlmsghdr *nlh, const struct bitwise_regs *regs,
                             uint32_t len, const void *mask, const void *xor)
{
  struct nlattr *expr, *data, *m, *x;

  expr = begin_nest(nlh, NFTA_LIST_ELEM);
  put_str(nlh, NFTA_EXPR_NAME, "bitwise");
  data = begin_nest(nlh, NFTA_EXPR_DATA);
  put_be32(nlh, NFTA_BITWISE_SREG, regs->sreg);
  put_be32(nlh, NFTA_BITWISE_DREG, regs->dreg);
  put_be32(nlh, NFTA_BITWISE_LEN, len);
  put_be32(nlh, NFTA_BITWISE_OP, NFT_BITWISE_MASK_XOR);
  m = begin_nest(nlh, NFTA_BITWISE_MASK);
  put_attr(nlh, NFTA_DATA_VALUE, len, mask);
  end_nest(nlh, m);
  x = begin_nest(nlh, NFTA_BITWISE_XOR);
  put_attr(nlh, NFTA_DATA_VALUE, len, xor);
  end_nest(nlh, x);
  end_nest(nlh, data);
  end_nest(nlh, expr);
}

/* ---- I/O helpers ---- */

/* ---- batch helpers ---- */

static struct nlmsghdr *batch_msg(char *buf, uint16_t type, uint16_t flags, uint16_t res_id)
{
  struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
  struct nfgenmsg *nfg;

  memset(nlh, 0, sizeof(*nlh) + sizeof(*nfg));
  nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
  nlh->nlmsg_type = type;
  nlh->nlmsg_flags = flags;
  nlh->nlmsg_seq = ++g_seq;
  nlh->nlmsg_pid = g_portid;
  nfg = (struct nfgenmsg *)NLMSG_DATA(nlh);
  nfg->nfgen_family = AF_UNSPEC;
  nfg->version = NFNETLINK_V0;
  nfg->res_id = htons(res_id);
  return nlh;
}

static int nl_batch_talk(char *buf, size_t len);

/* wrap a single nft command in a mini-batch (BEGIN + cmd + END) */
static int nl_talk_wrapped(const void *msg, size_t len)
{
  char batch_buf[BUF_SIZE];
  struct nlmsghdr *nlh;
  char *cur;

  memset(batch_buf, 0, sizeof(batch_buf));
  cur = batch_buf;

  nlh = batch_msg(cur, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES);
  cur += NLMSG_ALIGN(nlh->nlmsg_len);

  memcpy(cur, msg, len);
  cur += NLMSG_ALIGN(len);

  nlh = batch_msg(cur, NFNL_MSG_BATCH_END, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES);
  cur += NLMSG_ALIGN(nlh->nlmsg_len);

  return nl_batch_talk(batch_buf, (size_t)(cur - batch_buf));
}

static int nl_batch_talk(char *buf, size_t len)
{
  struct sockaddr_nl sa;
  ssize_t n;

  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;

  n = sendto(g_fd, buf, len, 0, (const struct sockaddr *)&sa, sizeof(sa));
  if (n < 0 || (size_t)n != len) {
    if (n >= 0)
      errno = EIO;
    return -1;
  }

  return process_batch_replies();
}

/* ---- helpers to optionally prepend iifname match ---- */

static void maybe_add_iifname(struct nlmsghdr *nlh, const char *iface)
{
  if (iface != NULL && iface[0] != '\0') {
    add_expr_meta_iifname(nlh, NFT_REG32_00);
    add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_EQ, iface, (uint32_t) strlen(iface) + 1);
  }
}

/* ---- batch construction helpers ---- */

static void netlink_delete_table(uint8_t family)
{
  char delbuf[BUF_SIZE];
  struct nlmsghdr *delhdr;

  memset(delbuf, 0, sizeof(delbuf));
  delhdr = msg_start(delbuf);
  msg_set(delhdr, NFT_MSG_DELTABLE, NLM_F_REQUEST | NLM_F_ACK, family);
  put_attr(delhdr, NFTA_TABLE_NAME, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
  nl_talk_wrapped(delbuf, delhdr->nlmsg_len);
}

static void add_table_batch(char **cur, uint8_t family)
{
  struct nlmsghdr *nlh = msg_start(*cur);

  msg_set(nlh, NFT_MSG_NEWTABLE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, family);
  put_attr(nlh, NFTA_TABLE_NAME, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
  {
    uint32_t flags = 0;
    put_attr(nlh, NFTA_TABLE_FLAGS, 4, &flags);
  }
  *cur += NLMSG_ALIGN(nlh->nlmsg_len);
}

static void add_chain_batch(char **cur, uint8_t family, const char *name, int base)
{
  struct nlmsghdr *nlh = msg_start(*cur);

  msg_set(nlh, NFT_MSG_NEWCHAIN, NLM_F_REQUEST | NLM_F_ACK, family);
  put_attr(nlh, NFTA_CHAIN_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
  put_attr(nlh, NFTA_CHAIN_NAME, (uint16_t) strlen(name) + 1, name);
  if (base) {
    struct nlattr *hook = begin_nest(nlh, NFTA_CHAIN_HOOK);
    uint32_t hooknum = bs32(1U);
    uint32_t prio = bs32((uint32_t) (-10));
    put_attr(nlh, NFTA_HOOK_HOOKNUM, 4, &hooknum);
    put_attr(nlh, NFTA_HOOK_PRIORITY, 4, &prio);
    end_nest(nlh, hook);
    put_str(nlh, NFTA_CHAIN_TYPE, "filter");
    {
      uint32_t flags = bs32(NFT_CHAIN_BASE);
      put_attr(nlh, NFTA_CHAIN_FLAGS, 4, &flags);
    }
    {
      uint32_t policy = bs32(NF_ACCEPT);
      put_attr(nlh, NFTA_CHAIN_POLICY, 4, &policy);
    }
  }
  *cur += NLMSG_ALIGN(nlh->nlmsg_len);
}

static int netlink_create_family_batch(uint8_t family)
{
  char buf[BUF_SIZE];
  char *cur;
  struct nlmsghdr *nlh;

  memset(buf, 0, sizeof(buf));
  cur = buf;

  /* BATCH_BEGIN */
  nlh = batch_msg(cur, NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES);
  cur += NLMSG_ALIGN(nlh->nlmsg_len);

  add_table_batch(&cur, family);
  add_chain_batch(&cur, family, CHAIN_NAME, 1);
  add_chain_batch(&cur, family, ALLOWED_NAME, 0);

  /* BATCH_END */
  nlh = batch_msg(cur, NFNL_MSG_BATCH_END, NLM_F_REQUEST, NFNL_SUBSYS_NFTABLES);
  cur += NLMSG_ALIGN(nlh->nlmsg_len);

  return nl_batch_talk(buf, (size_t)(cur - buf));
}

/* ---- public API ---- */

int netlink_init(void)
{
  /* open netlink socket */
  g_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
  if (g_fd < 0) {
    return -1;
  }
  g_seq = 0;

  {
    struct sockaddr_nl sa;
    socklen_t slen = sizeof(sa);

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(g_fd, (const struct sockaddr *)&sa, sizeof(sa)) != 0) {
      close(g_fd);
      g_fd = -1;
      return -1;
    }
    if (getsockname(g_fd, (struct sockaddr *)&sa, &slen) != 0) {
      close(g_fd);
      g_fd = -1;
      return -1;
    }
    g_portid = sa.nl_pid;
  }

  /* delete existing tables to reset kernel hgenerator */
  netlink_delete_table(AF_INET);
  netlink_delete_table(AF_INET6);

  if (netlink_create_family_batch(AF_INET) != 0) {
    close(g_fd);
    g_fd = -1;
    return -1;
  }

  if (netlink_create_family_batch(AF_INET6) != 0) {
    close(g_fd);
    g_fd = -1;
    return -1;
  }

  /* 6 objects: table + input chain + allowed_ips chain for each of 2 families */
  g_next_handle = 6;
  return 0;
}

int netlink_flush_chain(void)
{
  static const uint8_t fam[2] = { AF_INET, AF_INET6 };
  int i;

  for (i = 0; i < 2; i++) {
    char buf[BUF_SIZE];
    struct nlmsghdr *nlh;

    memset(buf, 0, sizeof(buf));
    nlh = msg_start(buf);
    msg_set(nlh, NFT_MSG_DELRULE, NLM_F_REQUEST | NLM_F_ACK, fam[i]);
    put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
    put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(ALLOWED_NAME) + 1, ALLOWED_NAME);
    nl_talk_wrapped(buf, nlh->nlmsg_len);
  }
  return 0;
}

int netlink_add_established_rule(const char *iface)
{
  static const uint8_t fam[2] = { AF_INET, AF_INET6 };
  int i;

  for (i = 0; i < 2; i++) {
    char buf[BUF_SIZE];
    struct nlmsghdr *nlh;
    uint32_t mask_val = 0x00000006U;
    uint32_t xor_val = 0;
    const uint8_t cmp_zero[4] = { 0, 0, 0, 0 };

    memset(buf, 0, sizeof(buf));
    nlh = msg_start(buf);
    msg_set(nlh, NFT_MSG_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE, fam[i]);
    put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
    put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(CHAIN_NAME) + 1, CHAIN_NAME);

    {
      struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

      maybe_add_iifname(nlh, iface);
      add_expr_ct_state(nlh, NFT_REG32_00);
      {
        const struct bitwise_regs br = { NFT_REG32_00, NFT_REG32_00 };

        add_expr_bitwise(nlh, &br, 4, &mask_val, &xor_val);
      }
      add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_NEQ, cmp_zero, 4);
      add_expr_immediate_verdict(nlh, NF_ACCEPT);

      end_nest(nlh, exprs);
    }

    if (nl_talk_wrapped(buf, nlh->nlmsg_len) != 0)
      return -1;
    g_next_handle++;
  }
  return 0;
}

static int add_drop_family(uint16_t port, const char *iface, uint8_t family)
{
  char buf[BUF_SIZE];
  struct nlmsghdr *nlh;
  const uint8_t tcp_val[1] = { 6 };
  uint16_t port_be = bs16(port);

  memset(buf, 0, sizeof(buf));
  nlh = msg_start(buf);
  msg_set(nlh, NFT_MSG_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE, family);
  put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
  put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(CHAIN_NAME) + 1, CHAIN_NAME);

  {
    struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

    maybe_add_iifname(nlh, iface);
    add_expr_meta_l4proto(nlh, NFT_REG32_00);
    add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_EQ, tcp_val, 1);
    add_expr_payload_load(nlh, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG32_00);
    add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_EQ, &port_be, 2);
    add_expr_immediate_verdict(nlh, NF_DROP);

    end_nest(nlh, exprs);
  }

  if (nl_talk_wrapped(buf, nlh->nlmsg_len) != 0)
    return -1;
  g_next_handle++;
  return 0;
}

int netlink_add_default_drop(uint16_t port, const char *iface)
{
  static const uint8_t fam[2] = { AF_INET, AF_INET6 };
  int i;

  for (i = 0; i < 2; i++) {
    if (add_drop_family(port, iface, fam[i]) != 0)
      return -1;
  }
  return 0;
}

int netlink_add_jump_allowed(void)
{
  static const uint8_t fam[2] = { AF_INET, AF_INET6 };
  int i;

  for (i = 0; i < 2; i++) {
    char buf[BUF_SIZE];
    struct nlmsghdr *nlh;

    memset(buf, 0, sizeof(buf));
    nlh = msg_start(buf);
    msg_set(nlh, NFT_MSG_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE, fam[i]);
    put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
    put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(CHAIN_NAME) + 1, CHAIN_NAME);

    {
      struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

      add_expr_immediate_verdict_chain(nlh, NFT_JUMP, ALLOWED_NAME);

      end_nest(nlh, exprs);
    }

    if (nl_talk_wrapped(buf, nlh->nlmsg_len) != 0)
      return -1;
    g_next_handle++;
  }
  return 0;
}

uint64_t netlink_rule_insert(const struct sockaddr_storage *src, uint16_t port, const char *iface)
{
  char buf[BUF_SIZE];
  struct nlmsghdr *nlh;
  uint16_t port_be = bs16(port);
  uint8_t family;

  family = src->ss_family;
  if (family != AF_INET && family != AF_INET6)
    return 0;

  memset(buf, 0, sizeof(buf));
  nlh = msg_start(buf);
  msg_set(nlh, NFT_MSG_NEWRULE, NLM_F_REQUEST | NLM_F_ACK | NLM_F_APPEND | NLM_F_CREATE, family);
  put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
  put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(ALLOWED_NAME) + 1, ALLOWED_NAME);
  put_be64(nlh, NFTA_RULE_HANDLE, g_next_handle);

  {
    struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

    maybe_add_iifname(nlh, iface);
    if (family == AF_INET) {
      const struct sockaddr_in *in = (const struct sockaddr_in *)src;
      add_expr_payload_load(nlh, NFT_PAYLOAD_NETWORK_HEADER, 12, 4, NFT_REG32_00);
      add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_EQ, &in->sin_addr, 4);
    } else {
      const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)src;
      add_expr_payload_load(nlh, NFT_PAYLOAD_NETWORK_HEADER, 8, 16, NFT_REG32_00);
      add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_EQ, &in6->sin6_addr, 16);
    }
    add_expr_payload_load(nlh, NFT_PAYLOAD_TRANSPORT_HEADER, 2, 2, NFT_REG32_00);
    add_expr_cmp(nlh, NFT_REG32_00, NFT_CMP_EQ, &port_be, 2);
    add_expr_immediate_verdict(nlh, NF_ACCEPT);

    end_nest(nlh, exprs);
  }

  if (nl_talk_wrapped(buf, nlh->nlmsg_len) != 0) {
    return 0;
  }

  return g_next_handle++;
}

int netlink_rule_delete(uint64_t handle, uint8_t family)
{
  char buf[BUF_SIZE];
  struct nlmsghdr *nlh;

  memset(buf, 0, sizeof(buf));
  nlh = msg_start(buf);
  msg_set(nlh, NFT_MSG_DELRULE, NLM_F_REQUEST | NLM_F_ACK, family);
  put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
  put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(ALLOWED_NAME) + 1, ALLOWED_NAME);
  put_be64(nlh, NFTA_RULE_HANDLE, handle);

  return nl_talk_wrapped(buf, nlh->nlmsg_len);
}

void netlink_cleanup(void)
{
  static const uint8_t fam[2] = { AF_INET, AF_INET6 };
  int i;

  if (g_fd < 0) {
    return;
  }

  for (i = 0; i < 2; i++) {
    char buf[BUF_SIZE] = { 0 };
    struct nlmsghdr *nlh = msg_start(buf);

    msg_set(nlh, NFT_MSG_DELRULE, NLM_F_REQUEST | NLM_F_ACK, fam[i]);
    put_attr(nlh, NFTA_RULE_TABLE, (uint16_t) strlen(TABLE_NAME) + 1, TABLE_NAME);
    put_attr(nlh, NFTA_RULE_CHAIN, (uint16_t) strlen(CHAIN_NAME) + 1, CHAIN_NAME);
    nl_talk_wrapped(buf, nlh->nlmsg_len);
    netlink_delete_table(fam[i]);
  }
  close(g_fd);
  g_fd = -1;
}
