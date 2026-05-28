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

## 1.1  CLI Interface

The daemon `totpgated` accepts:

| Argument | Default | Description |
|---|---|---|
| `--port` | `2222` | UDP port the daemon listens for TOTP packets |
| `--target-port` | `22` | TCP application port to protect |
| `--secret` | *(required)* | Shared secret (see §2.1 for encoding) |
| `--timeout` | `30` | Ephemeral rule lifetime in seconds |
| `--min-block` | `300` | Min rate-limit block duration in seconds |
| `--max-block` | `86400` | Max rate-limit block duration in seconds |
| `--rate-limit` | `5/60` | Max failed attempts per window (format `<n>/<window_s>`) |
| `--user` | `nobody` | Unprivileged user to run as after binding socket |
| `--group` | `nogroup` | Unprivileged group to run as after binding socket |
| `--foreground` | off | Log to stderr instead of syslog |

The client `totpgate` accepts:

| Argument | Default | Description |
|---|---|---|
| `--secret` | *(required)* | Shared secret (see §2.1 for encoding) |
| `--port` | `2222` | UDP port of the target daemon |
| `<server>` | *(required)* | IP or hostname of the daemon |
| `<target_port>` | — | Override default target port (optional) |

---

## 2.  Entities

### 2.1  `shared_secret`

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

### 2.2  `totp_token`

- 6–8 decimal digits (configurable, default 6).
- Computed as `Truncate(HMAC-SHA1(secret, time_counter)) mod 10^digits`.
- `time_counter = floor(UnixTime / time_step)`.
- Default time step: 30 seconds.

### 2.3  `auth_window`

| Parameter | Default | Description |
|---|---|---|
| `time_step` | 30 s | Width of each TOTP time window |
| `drift_ahead` | 1 | How many future windows are accepted |
| `drift_behind` | 1 | How many past windows are accepted |

The effective window size is `1 + drift_ahead + drift_behind` windows.
A token is valid if it matches **any** window in the range.

### 2.4  `auth_packet`

The UDP datagram sent by the client.  Wire format:

```
┌──────────────────────┐
│ TOTP token  (4–8 B)  │  ASCII decimal digits
│ separator   (1 B)    │  ':' (0x3A)  — optional
│ target_port (0–5 B)  │  ASCII decimal, 0 = config default
│ separator   (1 B)    │  ':' (0x3A)  — optional
│ lifetime    (0–5 B)  │  ASCII decimal seconds, 0 = config default
└──────────────────────┘
```

Minimal packet: just the token (e.g. `482639`).  
Extended packet with target port: `482639:443`.  
Full packet: `482639:443:120`.

The daemon parses from left to right; unknown trailing data is ignored.

### 2.5  `firewall_rule`

A netfilter rule inserted via netlink into the **nftables** `ip` family.
Attributes:

- **Table**: `totpgate` (created by daemon at startup).
- **Chain**: `input` (hook `NF_INET_LOCAL_IN`, priority 0).
- **Default policy**: `accept` (all non-matching traffic passes through).

**Permanent rules** (installed at startup, never expire):

| Priority | Match | Action |
|---|---|---|
| 0 | `ct state established,related` | `accept` |
| — | `tcp dport != <target_port>` | `accept` (skip non-target) |
| — | `tcp dport <target_port>` | `drop` (silent, unmatched SYN) |

**Ephemeral rules** (inserted on successful auth, auto-expire after
`--timeout` seconds):

| Match | Action |
|---|---|
| `ip saddr <client_ip> tcp dport <target_port> ct state new` | `accept` |

### 2.6  `auth_session`

Runtime record kept by the daemon for each authenticated client:

| Field | Type | Description |
|---|---|---|
| `src_ip` | `uint32_t` | Client IPv4 (network byte order) |
| `dst_port` | `uint16_t` | Target TCP port |
| `created` | `time_t` | When the rule was inserted |
| `lifetime` | `uint32_t` | Requested lifetime in seconds |
| `seq` | `uint64_t` | Monotonic counter (anti-replay) |

The daemon **may** prune expired sessions from its table on each event loop
iteration.  The kernel also auto-expires the rule, so the session table is
informational and used for logging / status.

---

## 3.  Business rules

### BR-1  Authentication

```
IF  received UDP datagram on <listen_port>
AND packet matches auth_packet format
AND TOTP(token, secret) is valid for at least one window in auth_window
THEN create or refresh firewall_rule for <sender_ip>:<target_port>
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
        create chain "input" (hook input, priority 0)
    flush chain "totpgate input"          // removes stale rules
    insert rule: ct state established,related accept   // permanent
    insert rule: tcp dport <target> drop              // default-drop
```

### BR-5  Auth-grant lifecycle

```
ON  successful authentication:
    insert rule: ip saddr <client_ip> tcp dport <target> ct state new accept
                  // auto-expires after <timeout> seconds
```

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
kernel automatically removes them after expiry.

---

## 4.  Lifecycle

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
  │      └─ insert: tcp dport <target> drop
  ├─ 3. Bind UDP socket to <port>
  ├─ 4. Drop privileges
  │
  └─ LOOP:
       ├─ 5. Wait for UDP datagram (poll with timeout)
       ├─ 6. Parse auth_packet
       ├─ 7. Validate TOTP
       ├─ 8. Check anti-replay seq counter
       ├─ 9. Insert nftables rule (--timeout seconds)
       ├─10. Log success / failure
       └─11. Prune expired auth session records
```

---

## 5.  Glossary

| Term | Definition |
|---|---|
| SPA | Single Packet Authorization — a single network packet that grants access |
| TOTP | Time-based One-Time Password (RFC 6238) |
| HMAC-SHA1 | Keyed-hash Message Authentication Code with SHA-1 (RFC 2104, RFC 3174) |
| Netlink | Linux kernel interface for modifying routing / firewall tables |
| nftables | Modern Linux packet classification framework (replacement for iptables) |
| Time step | Duration of each TOTP window (typically 30 s) |
| Drift | Number of windows before/after the current one that are still accepted |
