# DOMAIN — Business Rules & Entities

This document describes the core domain model of totpgate.  Agents MUST
consult this file before implementing or modifying behaviour.

---

## 1.  Overview

totpgate implements **Single Packet Authorization (SPA) using TOTP**.

An unprivileged client sends a single UDP datagram containing a time-based
one-time password.  The daemon validates the token against a pre-shared secret
and, on success, temporarily inserts a netfilter rule that allows the client's
IP to open a TCP connection to a protected port for 30 seconds.

---

## 2.  CLI Arguments

### 2.1  Daemon (`totpgated`)

| Argument | Default | Description |
|---|---|---|
| `--port` | `2222` | UDP listen port. When no IP is given, binds **both** `0.0.0.0:2222` (IPv4) and `[::]:2222` (IPv6, `IPV6_V6ONLY=1`). May be given multiple times with optional IP binding (`[ip:]port`, e.g. `0.0.0.0:2222` or `[::]:2222`). |
| `--interface` | — | Network interface (e.g. `eth0`) to bind firewall `iifname` matches to. If omitted, rules match on any interface. |
| `--target-port` | `22` | TCP application port to protect |
| `--secret` | *(required)* | Shared secret (see §3.1 for encoding); mutually exclusive with `--secret-file` |
| `--secret-file` | — | Path to file containing the shared secret (see §3.1 for encoding); mutually exclusive with `--secret` |
| `--timeout` | `30` | Ephemeral rule lifetime in seconds |
| `--min-block` | `300` | Min rate-limit block duration in seconds |
| `--max-block` | `86400` | Max rate-limit block duration in seconds |
| `--rate-limit` | `5/60` | Max failed attempts per window (format `<n>/<window_s>`) |
| `--user` | `nobody` | Unprivileged user to run as after binding socket |
| `--group` | `nogroup` | Unprivileged group to run as after binding socket |
| `--foreground` | off | Log to stderr instead of syslog |

### 2.2  Client (`totpgate`)

| Argument | Default | Description |
|---|---|---|
| `--secret` | *(required)* | Shared secret (see §3.1 for encoding) |
| `--port` | `2222` | UDP port of the target daemon |
| `<server>` | *(required)* | IP or hostname of the daemon. May include `:port` suffix to override `--port`. IPv6 addresses must use bracket notation (`[::1]:2222`). Bare IPv6 addresses without a port are accepted (e.g. `::1`). |

---

## 3.  Entities

### 3.1  `shared_secret`

- Opaque byte array (≥ 16 bytes, recommended 32).
- Known to both client and daemon _a priori_.
- **Never** transmitted over the wire.

#### Encoding prefix dispatch

The `--secret` argument is a string with an optional prefix that selects the
decoding scheme:

| Prefix | Encoding | Example |
|---|---|---|
| *(none)* | Base32 (RFC 4648) | `JBSWY3DPEHPK3PXP` |
| `hex:` | Hexadecimal, case-insensitive | `hex:48656c6c6f` |
| `b64:` | Base64 (RFC 4648, standard alphabet with `=`) | `b64:SGVsbG8=` |

Internally all three are decoded into the same raw byte array before any
cryptographic operation.  The prefix is stripped during parsing and is not
part of the encoded payload.

Decoding rules:
- Base32: reject characters outside RFC 4648 alphabet, reject invalid padding.
- Hex: reject non-hex characters (`0-9`, `a-f`, `A-F` only); accept both
  cases; accept odd-length input (implicit leading zero).
- Base64: reject characters outside RFC 4648 standard alphabet; reject invalid
  padding; handle embedded whitespace.

### 3.2  `totp_token`

- 6 decimal digits (hardcoded in both client and daemon).
- Computed as `Truncate(HMAC-SHA1(secret, time_counter)) mod 10^6`.
- `time_counter = floor(UnixTime / time_step)`.
- Time step: 30 seconds (hardcoded).

### 3.3  `auth_window`

| Parameter | Value | Description |
|---|---|---|
| `time_step` | 30 s | Width of each TOTP time window (hardcoded) |
| `drift_ahead` | 1 | How many future windows are accepted (hardcoded) |
| `drift_behind` | 1 | How many past windows are accepted (hardcoded) |

The effective window size is `1 + drift_ahead + drift_behind` windows.
A token is valid if it matches **any** window in the range.  None of these
parameters are user-configurable.

### 3.4  `auth_packet`

The UDP datagram sent by the client.  Wire format:

```
┌──────────────────────┐
│ TOTP token  (6–8 B)  │  ASCII decimal digits
└──────────────────────┘
```

The packet contains only the token (e.g. `482639`).  The daemon rejects any
packet with trailing data.  The target port and rule lifetime are controlled
exclusively by the daemon's `--target-port` and `--timeout` options.

### 3.5  `firewall_rule`

Netfilter rules inserted via netlink into the **nftables** `ip` and `ip6` families.

The daemon manages two chains in the `totpgate` table:

- **`input`** — base hook (`NF_INET_LOCAL_IN`, priority -10), default
  policy `accept`.  Contains permanent rules evaluated in order.
- **`allowed_ips`** — regular chain (no hook).  Contains ephemeral
  rules that are only reached via a jump from `input`.

**Permanent rules** (in `input` chain, installed at startup, never expire):

| Match | Action |
|---|---|
| `ct state established,related` | `accept` |
| *(no match)* | `jump allowed_ips` |
| `[iifname <interface>] tcp dport <target_port>` | `drop` (silent, unmatched SYN) |

Traffic that reaches the end of `allowed_ips` (no ephemeral match) returns
to `input` and hits the drop rule.  Non-target traffic never matches the
drop rule and falls through to the chain's default `accept` policy.

**Ephemeral rules** (in `allowed_ips` chain, inserted on successful auth,
auto-expire after `--timeout` seconds):

| Match | Action |
|---|---|
| `[iifname <interface>] ip saddr <client_ip> tcp dport <target_port>` | `accept` (`ip` family) |
| `[iifname <interface>] ip6 saddr <client_ip> tcp dport <target_port>` | `accept` (`ip6` family) |

The ephemeral rule omits `ct state new` because the permanent
`established,related accept` rule is evaluated first in `input` and
catches non-new packets before the jump.

### 3.6  `auth_session`

Runtime record kept by the daemon for each authenticated client:

| Field | Type | Description |
|---|---|---|
| `src_ip` | `ip_addr_t` | Client address (family + 16‑byte payload). IPv4 addresses are stored in the first 4 bytes with the rest zero‑padded. |
| `dst_port` | `uint16_t` | Target TCP port |
| `created` | `time_t` | When the rule was inserted |
| `lifetime` | `uint32_t` | Rule lifetime in seconds (from `--timeout`) |
| `seq` | `uint64_t` | Monotonic counter (anti-replay) |

The daemon **may** prune expired sessions from its table on each event loop
iteration.  The kernel also auto-expires the rule, so the session table is
informational and used for logging / status.

---

## 4.  Business Rules

### BR-1  Authentication

```
IF  received UDP datagram on <listen_port>
AND packet matches auth_packet format
AND TOTP(token, secret) is valid for at least one window in auth_window
THEN create or refresh firewall_rule for <sender_ip>:<daemon_target_port>
```

### BR-2  Token validity

```
A TOTP token is valid IF
  HMAC-SHA1(secret, T_floor(now + drift * time_step)) mod 10^digits == token
  FOR ANY drift in [-drift_behind .. +drift_ahead]
```

### BR-3  Anti-replay

```
A token that was already accepted in the current time window MUST be rejected.
```

Implementation: store `seq` (the time counter value) per source IP.  Refuse a
token whose counter ≤ stored counter for that IP.

Note: because each window is 30 s wide, a token could be replayed within the
same window.  The `seq` counter prevents this.

### BR-4  Startup firewall setup

```
ON  startup:
    IF  table "totpgate" does not exist:
        create table "totpgate"
    IF  chain "input" does not exist:
        create chain "input" (hook input, priority -10, policy accept)
    create chain "allowed_ips"                              (regular chain)
    flush chain "totpgate input"                 // removes stale rules
    insert rule (input): ct state established,related accept   // permanent
    insert rule (input): jump allowed_ips
    insert rule (input): [iifname <interface>] tcp dport <target> drop
```

The `input` chain is evaluated in order: established/related traffic is
accepted immediately; remaining packets jump to `allowed_ips` for
dynamic matching; unmatched SYN packets to the target port are silently
dropped.  Non-target traffic falls through to the default `accept` policy.

If `--interface` was given, the drop rule (and every rule in `allowed_ips`)
includes an `iifname <interface>` match so that rules only apply to packets
arriving on that interface.

### BR-5  Auth-grant lifecycle

```
ON  successful authentication:
    append rule (allowed_ips): [iifname <interface>] <family> saddr <client_ip> tcp dport <target> accept
                  // <family> is `ip` for AF_INET and `ip6` for AF_INET6.
                  // IPv4 clients arrive on the separate AF_INET socket — no
                  // IPv4-mapped IPv6 addresses reach the firewall layer.
                  // auto-expires after <timeout> seconds
```

The rule is appended to the `allowed_ips` chain.  It omits `ct state new`
— the permanent `established,related accept` rule (BR-4) is evaluated
first, so the ephemeral rule only ever sees non-established, non-related
packets.

### BR-6  Privilege drop

```
AFTER  UDP socket is bound (< 1024 requires CAP_NET_BIND_SERVICE):
    setgroups(gid), setgid(gid), setuid(uid)
    prctl(PR_SET_NO_NEW_PRIVS, 1)
    // defaults: user=nobody, group=nogroup; overridable via
    // --user / --group
```

### BR-7  Ephemeral rule timeout

Auth-granted rules have a lifetime set by `--timeout` (default 30 s).  The
daemon tracks each rule's handle and expiry time in a fixed-size array;
every 5 s the event loop prunes expired rules via `netlink_rule_delete()`.

### BR-8  Rate limiting

```
ON  auth failure from <ip>:
    IF  fail window has expired (≥ <window> s since first_fail):
        reset fail_count to 1, first_fail to now     // fresh window
    ELSE:
        increment fail_count
        IF  fail_count >= <max_fails> AND NOT currently blocked:
            set block_duration = min(<max_block>, max(<min_block>, 2 * previous_block_duration))
            block <ip> until now + block_duration     // exponential backoff

ON  auth success from <ip>:
    clear <ip>'s rate-limit entry entirely            // fail_count, block_until, block_duration reset to zero
```

- The first block always uses `<min_block>` seconds.
- Each subsequent block doubles the duration, capped at `<max_block>`.
- A successful authentication erases the entry, so the next block cycle starts
  from `<min_block>` again.
- Default: 5 failures in a 60-second window → 300 s block, doubling up to
  86400 s (24 h).

---

## 5.  Flow / Lifecycle

```
START
  │
  ├─ 1. Parse CLI arguments (--port, --target-port, --secret, --timeout)
  │      └─ decode secret: detect prefix → base32 / hex / b64 decode → raw bytes
  ├─ 2. Validate & prepare nftables table
  │      ├─ create table "totpgate" if missing
  │      ├─ create chain "input" if missing
  │      ├─ flush chain (remove stale rules from prior session)
  │      ├─ insert: ct state established,related accept
  │      └─ insert: [iifname <interface>] tcp dport <target> drop
  ├─ 3. Bind UDP socket(s) — iterate each --port entry, resolve address, bind.
  │      When no --port is given, binds two sockets: `0.0.0.0:2222` (AF_INET)
  │      and `[::]:2222` (AF_INET6 with `IPV6_V6ONLY=1`).
  ├─ 4. Drop privileges
  │
  └─ LOOP:
       ├─ 5. Wait for UDP datagram (epoll with timeout)
       ├─ 6. Parse auth_packet
       ├─ 7. Validate TOTP
       ├─ 8. Check anti-replay seq counter
       ├─ 9. Insert nftables rule (--timeout seconds)
       ├─10. Log success / failure
       └─11. Prune expired auth session records
```

---

## 6.  Retry Landscape

| Scenario | Mechanism | Max trials | Backoff | Notes |
|---|---|---|---|---|
| Auth failure (per-IP) | Rate-limit window + exponential block | Unlimited (window resets) | 2× per cycle, min_block → max_block | See BR-8 |
| UDP socket read | epoll_wait returns ready; non-blocking recvfrom | N/A (event-driven) | None | EAGAIN terminates burst |

No network-level retry is implemented.  The client sends one UDP datagram and
exits.  Retry is the caller's responsibility.

---

## 7.  Dynamic Arrays (Grow / Shrink)

No dynamic arrays are used.  All data structures use fixed-size pre-allocated
arrays:

| Structure | Type | Size | Notes |
|---|---|---|---|
| Session table | Fixed array | `MAX_SESSIONS` (128) | SLAB-style free list |
| Rate-limit table | Fixed array | `MAX_RATELIMIT` (1024) | Linear-probed open addressing |
| epoll events | Fixed array | RLIMIT_NOFILE | Allocated once at startup |

---

## 8.  Hash Maps (Bucket Grow / Shrink)

No hash maps with dynamic bucket growth are used.  The rate-limit table uses a
fixed-size open-addressing scheme with linear probing and a probe budget.
There is no resizing — entries are recycled on expiry.

---

## 9.  Thread / Worker / Parallelism Landscape

The daemon is **single-threaded**.  All I/O is multiplexed via epoll
(edge-triggered).  There are no worker threads, no mutexes, and no shared
mutable state between threads.

Signal handling uses a self-pipe trick: the signal handler writes a byte to a
pipe whose read end is registered in the epoll set.

---

## 10.  Glossary

| Term | Definition |
|---|---|
| SPA | Single Packet Authorization — a single network packet that grants access |
| TOTP | Time-based One-Time Password (RFC 6238) |
| HMAC-SHA1 | Keyed-hash Message Authentication Code with SHA-1 (RFC 2104, RFC 3174) |
| Netlink | Linux kernel interface for modifying routing / firewall tables |
| nftables | Modern Linux packet classification framework (replacement for iptables) |
| Time step | Duration of each TOTP window (typically 30 s) |
| Drift | Number of windows before/after the current one that are still accepted |
