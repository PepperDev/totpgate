#include "netlink.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

#define TABLE_NAME  "totpgate"
#define CHAIN_NAME  "input"
#define BUF_SIZE    4096

static int      g_fd = -1;
static uint32_t g_seq;
static uint64_t g_drop_handle;

/* helpers for raw byte-order conversion without <arpa/inet.h> */

static uint16_t bs16(uint16_t x)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (uint16_t)((x << 8) | (x >> 8));
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

/* ---- netlink message helpers ---- */

static struct nlmsghdr *msg_start(char *buf)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

	memset(nlh, 0, sizeof(*nlh));
	nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct nfgenmsg));
	nlh->nlmsg_seq = ++g_seq;
	nlh->nlmsg_pid = 0;
	return nlh;
}

static struct nfgenmsg *msg_nfg(struct nlmsghdr *nlh)
{
	return (struct nfgenmsg *)NLMSG_DATA(nlh);
}

static void msg_set(struct nlmsghdr *nlh, uint16_t type, uint16_t flags,
		    uint8_t family)
{
	struct nfgenmsg *nfg = msg_nfg(nlh);

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = flags;
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = 0;
}

static struct nlattr *put_attr(struct nlmsghdr *nlh, uint16_t type,
			       uint16_t plen, const void *data)
{
	uint16_t total = NLA_HDRLEN + plen;
	int pad = (int)NLA_ALIGN(total) - (int)total;
	struct nlattr *nla;

	nla = (struct nlattr *)((char *)nlh
				+ NLMSG_ALIGN(nlh->nlmsg_len));
	nla->nla_len = total;
	nla->nla_type = type;
	if (data && plen > 0) {
		memcpy((char *)nla + NLA_HDRLEN, data, plen);
	}
	nlh->nlmsg_len = NLMSG_ALIGN(nlh->nlmsg_len) + NLA_ALIGN(total);
	if (pad > 0) {
		memset((char *)nlh + nlh->nlmsg_len - pad, 0,
		       (size_t)pad);
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
	nla->nla_len = (uint16_t)((char *)nlh + nlh->nlmsg_len
				  - (char *)nla);
}

/* convenience: put a NUL-terminated string attribute */
static void put_str(struct nlmsghdr *nlh, uint16_t type, const char *s)
{
	put_attr(nlh, type, (uint16_t)(strlen(s) + 1), s);
}

/* ---- expression builders (append to the rule's NFTA_RULE_EXPRESSIONS) ---- */

static void add_expr_immediate_verdict(struct nlmsghdr *nlh, uint32_t verdict)
{
	struct nlattr *expr, *data, *vd;
	uint32_t reg = NFT_REG_VERDICT;

	expr = begin_nest(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "immediate");
	data = begin_nest(nlh, NFTA_EXPR_DATA);
	put_attr(nlh, NFTA_IMMEDIATE_DREG, 4, &reg);
	vd = begin_nest(nlh, NFTA_IMMEDIATE_DATA);
	{
		struct nlattr *vd2 = begin_nest(nlh, NFTA_DATA_VERDICT);

		put_attr(nlh, NFTA_VERDICT_CODE, 4, &verdict);
		end_nest(nlh, vd2);
	}
	end_nest(nlh, vd);
	end_nest(nlh, data);
	end_nest(nlh, expr);
}

static void add_expr_payload_load(struct nlmsghdr *nlh, uint32_t base,
				  uint32_t offset, uint32_t len,
				  uint32_t dreg)
{
	struct nlattr *expr, *data;

	expr = begin_nest(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "payload");
	data = begin_nest(nlh, NFTA_EXPR_DATA);
	put_attr(nlh, NFTA_PAYLOAD_DREG, 4, &dreg);
	put_attr(nlh, NFTA_PAYLOAD_BASE, 4, &base);
	put_attr(nlh, NFTA_PAYLOAD_OFFSET, 4, &offset);
	put_attr(nlh, NFTA_PAYLOAD_LEN, 4, &len);
	end_nest(nlh, data);
	end_nest(nlh, expr);
}

static void add_expr_cmp(struct nlmsghdr *nlh, uint32_t sreg,
			 uint32_t op, const void *data, uint32_t dlen)
{
	struct nlattr *expr, *edata, *vd;

	expr = begin_nest(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "cmp");
	edata = begin_nest(nlh, NFTA_EXPR_DATA);
	put_attr(nlh, NFTA_CMP_SREG, 4, &sreg);
	put_attr(nlh, NFTA_CMP_OP, 4, &op);
	vd = begin_nest(nlh, NFTA_CMP_DATA);
	put_attr(nlh, NFTA_DATA_VALUE, dlen, data);
	end_nest(nlh, vd);
	end_nest(nlh, edata);
	end_nest(nlh, expr);
}

static void add_expr_meta_l4proto(struct nlmsghdr *nlh, uint32_t dreg)
{
	struct nlattr *expr, *data;
	uint32_t key = NFT_META_L4PROTO;

	expr = begin_nest(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "meta");
	data = begin_nest(nlh, NFTA_EXPR_DATA);
	put_attr(nlh, NFTA_META_DREG, 4, &dreg);
	put_attr(nlh, NFTA_META_KEY, 4, &key);
	end_nest(nlh, data);
	end_nest(nlh, expr);
}

static void add_expr_ct_state(struct nlmsghdr *nlh, uint32_t dreg)
{
	struct nlattr *expr, *data;
	uint32_t key = NFT_CT_STATE;

	expr = begin_nest(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "ct");
	data = begin_nest(nlh, NFTA_EXPR_DATA);
	put_attr(nlh, NFTA_CT_DREG, 4, &dreg);
	put_attr(nlh, NFTA_CT_KEY, 4, &key);
	end_nest(nlh, data);
	end_nest(nlh, expr);
}

static void add_expr_bitwise(struct nlmsghdr *nlh, uint32_t sreg,
			     uint32_t dreg, uint32_t len,
			     const void *mask, const void *xor)
{
	struct nlattr *expr, *data, *m, *x;
	uint32_t op = NFT_BITWISE_MASK_XOR;

	expr = begin_nest(nlh, NFTA_LIST_ELEM);
	put_str(nlh, NFTA_EXPR_NAME, "bitwise");
	data = begin_nest(nlh, NFTA_EXPR_DATA);
	put_attr(nlh, NFTA_BITWISE_SREG, 4, &sreg);
	put_attr(nlh, NFTA_BITWISE_DREG, 4, &dreg);
	put_attr(nlh, NFTA_BITWISE_LEN, 4, &len);
	put_attr(nlh, NFTA_BITWISE_OP, 4, &op);
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

static int nl_send_recv(const void *msg, size_t len,
			void *reply, size_t *reply_len)
{
	struct sockaddr_nl sa;
	ssize_t n;

	memset(&sa, 0, sizeof(sa));
	sa.nl_family = AF_NETLINK;

	n = sendto(g_fd, msg, len, 0,
		   (const struct sockaddr *)&sa, sizeof(sa));
	if (n < 0 || (size_t)n != len) {
		if (n >= 0) {
			errno = EIO;
		}
		return -1;
	}

	n = recv(g_fd, reply, *reply_len, 0);
	if (n < 0) {
		return -1;
	}
	*reply_len = (size_t)n;
	return 0;
}

static int nl_talk(const void *msg, size_t len)
{
	char reply[BUF_SIZE];
	size_t rlen = sizeof(reply);
	struct nlmsghdr *nlh;

	if (nl_send_recv(msg, len, reply, &rlen) != 0) {
		return -1;
	}
	if (rlen < sizeof(struct nlmsghdr)) {
		errno = EPROTO;
		return -1;
	}

	nlh = (struct nlmsghdr *)reply;
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		struct nlmsgerr *er = (struct nlmsgerr *)NLMSG_DATA(nlh);

		if (er->error != 0) {
			errno = -er->error;
			return -1;
		}
		return 0;               /* success ack */
	}
	/* success (no ack requested — shouldn't happen with NLM_F_ACK) */
	return 0;
}

/* parse the first u64 attribute of given type from a netlink reply */
static int nl_parse_u64(const void *reply, size_t rlen,
			uint16_t want_type, uint64_t *val)
{
	const struct nlmsghdr *nlh = (const struct nlmsghdr *)reply;
	size_t remaining;
	struct nlattr *attr;
	int off;

	if (rlen < sizeof(*nlh)) {
		return -1;
	}
	remaining = rlen - NLMSG_LENGTH(sizeof(struct nfgenmsg));
	off = 0;

	while (off + (int)sizeof(struct nlattr) <= (int)remaining) {
		attr = (struct nlattr *)((char *)NLMSG_DATA(nlh)
					 + sizeof(struct nfgenmsg) + off);
		if (attr->nla_len < sizeof(struct nlattr)) {
			break;
		}
		if ((attr->nla_type & NLA_TYPE_MASK) == want_type) {
			if (attr->nla_len >= NLA_HDRLEN + 8) {
				memcpy(val,
				       (const char *)attr + NLA_HDRLEN, 8);
				return 0;
			}
		}
		off += (int)NLA_ALIGN(attr->nla_len);
	}
	return -1;
}

/* ---- public API ---- */

int netlink_init(void)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;

	/* open netlink socket */
	g_fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
	if (g_fd < 0) {
		return -1;
	}
	g_seq = 0;

	/* --- create table --- */
	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_NEWTABLE,
		NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, AF_INET);
	put_attr(nlh, NFTA_TABLE_NAME,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);

	if (nl_talk(buf, nlh->nlmsg_len) != 0) {
		/* EEXIST is fine — table already exists */
		if (errno != EEXIST) {
			close(g_fd);
			g_fd = -1;
			return -1;
		}
	}

	/* --- create chain --- */
	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_NEWCHAIN,
		NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, AF_INET);
	put_attr(nlh, NFTA_CHAIN_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_CHAIN_NAME,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);
	{
		struct nlattr *hook = begin_nest(nlh, NFTA_CHAIN_HOOK);
		uint32_t hooknum = NF_INET_LOCAL_IN;
		uint32_t prio = 0;

		put_attr(nlh, NFTA_HOOK_HOOKNUM, 4, &hooknum);
		put_attr(nlh, NFTA_HOOK_PRIORITY, 4, &prio);
		end_nest(nlh, hook);
	}
	{
		uint32_t policy = NF_ACCEPT;

		put_attr(nlh, NFTA_CHAIN_POLICY, 4, &policy);
	}

	if (nl_talk(buf, nlh->nlmsg_len) != 0) {
		if (errno != EEXIST) {
			close(g_fd);
			g_fd = -1;
			return -1;
		}
	}

	return 0;
}

int netlink_flush_chain(void)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_DELRULE,
		NLM_F_REQUEST | NLM_F_ACK, AF_INET);
	put_attr(nlh, NFTA_RULE_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_RULE_CHAIN,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);

	return nl_talk(buf, nlh->nlmsg_len);
}

int netlink_add_established_rule(void)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;
	uint32_t reg = NFT_REG32_00;
	/* ct state bitmask: established(0x02) | related(0x04) = 0x06 */
	uint32_t mask_be = bs32(0x00000006U);
	uint32_t xor_be = 0;
	uint8_t cmp_zero[4] = { 0, 0, 0, 0 };
	uint32_t neq = NFT_CMP_NEQ;

	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_NEWRULE,
		NLM_F_REQUEST | NLM_F_ACK, AF_INET);
	put_attr(nlh, NFTA_RULE_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_RULE_CHAIN,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);

	{
		struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

		add_expr_ct_state(nlh, reg);
		add_expr_bitwise(nlh, reg, reg, 4, &mask_be, &xor_be);
		add_expr_cmp(nlh, reg, neq, cmp_zero, 4);
		add_expr_immediate_verdict(nlh, NF_ACCEPT);

		end_nest(nlh, exprs);
	}

	return nl_talk(buf, nlh->nlmsg_len);
}

int netlink_add_default_drop(uint16_t port)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;
	uint32_t reg = NFT_REG32_00;
	uint8_t tcp_val[1] = { 6 };
	uint32_t eq = NFT_CMP_EQ;
	uint32_t base = NFT_PAYLOAD_TRANSPORT_HEADER;
	uint16_t port_be = bs16(port);

	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_NEWRULE,
		NLM_F_REQUEST | NLM_F_ECHO, AF_INET);
	put_attr(nlh, NFTA_RULE_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_RULE_CHAIN,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);

	{
		struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

		add_expr_meta_l4proto(nlh, reg);
		add_expr_cmp(nlh, reg, eq, tcp_val, 1);
		add_expr_payload_load(nlh, base, 2, 2, reg);
		add_expr_cmp(nlh, reg, eq, &port_be, 2);
		add_expr_immediate_verdict(nlh, NF_DROP);

		end_nest(nlh, exprs);
	}

	{
		char reply[BUF_SIZE];
		size_t rlen = sizeof(reply);
		struct nlmsghdr *rh;
		uint64_t h = 0;

		if (nl_send_recv(buf, nlh->nlmsg_len, reply, &rlen) != 0) {
			return -1;
		}
		rh = (struct nlmsghdr *)reply;
		if (rlen >= sizeof(*rh)
		    && rh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *er;

			er = (struct nlmsgerr *)NLMSG_DATA(rh);
			if (er->error != 0) {
				return -1;
			}
		}
		if (nl_parse_u64(reply, rlen,
				 NFTA_RULE_HANDLE, &h) == 0) {
			g_drop_handle = h;
		}
	}

	return 0;
}

uint64_t netlink_rule_insert(uint32_t ip, uint16_t port)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;
	char reply[BUF_SIZE];
	size_t rlen = sizeof(reply);
	uint32_t reg = NFT_REG32_00;
	uint32_t eq = NFT_CMP_EQ;
	uint32_t base_n = NFT_PAYLOAD_NETWORK_HEADER;
	uint32_t base_t = NFT_PAYLOAD_TRANSPORT_HEADER;
	uint32_t ip_be = bs32(ip);
	uint16_t port_be = bs16(port);

	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_NEWRULE,
		NLM_F_REQUEST | NLM_F_ECHO, AF_INET);
	put_attr(nlh, NFTA_RULE_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_RULE_CHAIN,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);

	if (g_drop_handle != 0) {
		put_attr(nlh, NFTA_RULE_POSITION, 8, &g_drop_handle);
	}

	{
		struct nlattr *exprs = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);

		add_expr_payload_load(nlh, base_n, 12, 4, reg);
		add_expr_cmp(nlh, reg, eq, &ip_be, 4);
		add_expr_payload_load(nlh, base_t, 2, 2, reg);
		add_expr_cmp(nlh, reg, eq, &port_be, 2);
		add_expr_immediate_verdict(nlh, NF_ACCEPT);

		end_nest(nlh, exprs);
	}

	if (nl_send_recv(buf, nlh->nlmsg_len, reply, &rlen) != 0) {
		return 0;
	}

	{
		uint64_t h = 0;
		struct nlmsghdr *rh = (struct nlmsghdr *)reply;

		if (rlen < sizeof(*rh)) {
			return 0;
		}
		if (rh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *er;

			er = (struct nlmsgerr *)NLMSG_DATA(rh);
			if (er->error != 0) {
				return 0;
			}
		}
		if (nl_parse_u64(reply, rlen,
				 NFTA_RULE_HANDLE, &h) != 0) {
			return h;
		}
		return h;
	}
}

int netlink_rule_delete(uint64_t handle)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;

	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_DELRULE,
		NLM_F_REQUEST | NLM_F_ACK, AF_INET);
	put_attr(nlh, NFTA_RULE_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_RULE_CHAIN,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);
	put_attr(nlh, NFTA_RULE_HANDLE, 8, &handle);

	return nl_talk(buf, nlh->nlmsg_len);
}

void netlink_cleanup(void)
{
	char buf[BUF_SIZE];
	struct nlmsghdr *nlh;

	if (g_fd < 0) {
		return;
	}

	/* flush chain */
	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_DELRULE,
		NLM_F_REQUEST | NLM_F_ACK, AF_INET);
	put_attr(nlh, NFTA_RULE_TABLE,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	put_attr(nlh, NFTA_RULE_CHAIN,
		 (uint16_t)strlen(CHAIN_NAME) + 1, CHAIN_NAME);
	nl_talk(buf, nlh->nlmsg_len);

	/* delete table */
	memset(buf, 0, sizeof(buf));
	nlh = msg_start(buf);
	msg_set(nlh, NFT_MSG_DELTABLE,
		NLM_F_REQUEST | NLM_F_ACK, AF_INET);
	put_attr(nlh, NFTA_TABLE_NAME,
		 (uint16_t)strlen(TABLE_NAME) + 1, TABLE_NAME);
	nl_talk(buf, nlh->nlmsg_len);

	close(g_fd);
	g_fd = -1;
}
