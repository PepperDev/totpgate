# DOMAIN — Business Rules & Entities

This document describes the core domain model of totpgate.  Agents MUST
consult this file before implementing or modifying behaviour.

---

## 1.  Overview

totpgate implements **Single Packet Authorization (SPA) using TOTP**.

An unprivileged client sends a single UDP datagram containing a time-based
one-time password.  The daemon validates the token against a pre-shared secret
and, on success, temporarily inserts a netfilter rule that allows the client's
IP to connect to a protected TCP port.

---

## 2.  Entities

### 2.1  `shared_secret`

- Opaque byte array (≥ 16 bytes, recommended 32).
- Base32-encoded in configuration (RFC 4648).
- Known to both client and daemon _a priori_.
- **Never** transmitted over the wire.

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
- **Match**: `src <client_ip>`, `tcp dport <target_port>`.
- **Action**: `accept`.
- **Expiration**: set via nftables timeout mechanism.
- **Handle**: returned by kernel on insert; used for early delete on
  re-authentication.

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

### BR-4  Firewall rule lifecycle

```
ON  successful authentication:
    IF  a rule for <src_ip>:<dst_port> already exists:
        (a) delete old rule using its handle
        (b) insert new rule with fresh timeout
    ELSE:
        insert new rule with timeout <lifetime>
```

### BR-5  Privilege drop

```
AFTER  UDP socket is bound (< 1024 requires CAP_NET_BIND_SERVICE):
    drop all capabilities, setuid/gid to <unprivileged_user>
```

### BR-6  Configuration file

Format: `KEY=VALUE` lines, one per line.  Lines starting with `#` are
comments.  Keys:

| Key | Required | Default | Description |
|---|---|---|---|
| `SECRET` | yes | — | Base32-encoded shared secret |
| `LISTEN_PORT` | yes | — | UDP port the daemon listens on |
| `TARGET_PORT` | yes | — | Default TCP port to protect |
| `ALLOWED_USERS` | no | `nobody:nogroup` | `user:group` to drop to |
| `AUTH_TIMEOUT` | no | `60` | Default rule lifetime (seconds) |
| `TOTP_DIGITS` | no | `6` | Number of TOTP digits (6–8) |
| `TOTP_STEP` | no | `30` | TOTP time step (seconds) |
| `DRIFT_AHEAD` | no | `1` | Future windows to accept |
| `DRIFT_BEHIND` | no | `1` | Past windows to accept |

---

## 4.  Lifecycle

```
START
  │
  ├─ 1. Load & validate configuration
  ├─ 2. Create nftables table & chain (totpgate/input)
  ├─ 3. Bind UDP socket to <listen_port>
  ├─ 4. Drop privileges
  │
  └─ LOOP:
       ├─ 5. Wait for UDP datagram (poll with timeout)
       ├─ 6. Parse auth_packet
       ├─ 7. Validate TOTP
       ├─ 8. Check anti-replay seq counter
       ├─ 9. Insert / refresh nftables rule
       ├─10. Log success / failure
       └─11. Prune expired sessions
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
