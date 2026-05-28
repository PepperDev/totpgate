# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

## Project Foundation

- [x] Create Makefile with static musl build, test, style, coverage targets
- [x] Create directory layout: `src/`, `test/`, `bin/`, `obj/`
- [x] Create `src/main.c` with CLI option parsing using `getopt_long`:
      `--port` (default 2222), `--target-port` (default 22),
      `--secret`, `--timeout` (default 30), `--foreground`
- [x] Create headers: `sha1.h`, `hmac.h`, `totp.h`, `netlink.h`, `udp.h`,
      `encode.h`, `auth.h`, `util.h`
- [x] Create `test/test_runner.h` with test macros
- [x] Create `test/test_runner.c` with passing harness
- [x] `make test` passes
- [x] `make style` runs (verified idempotent on clean code)

> **Note:** `musl-gcc` is not available on this system — build falls back to
> `cc` (gcc).  Install `musl-gcc` for production static builds.  `indent` is
> available.

## SHA-1 Implementation

- [ ] Implement `sha1.c` — SHA-1 hash per RFC 3174
- [ ] Unit tests: empty input, short string, known NIST vectors
- [ ] ≥ 80 % line coverage on `sha1.c`
- [ ] Zero warnings on `sha1.c`

## HMAC-SHA1 Implementation

- [ ] Implement `hmac.c` — HMAC per RFC 2104 with SHA-1
- [ ] Unit tests: RFC 2202 known test vectors (key <= 64, key > 64, empty key)
- [ ] ≥ 80 % line coverage on `hmac.c`

## TOTP Implementation

- [ ] Implement `totp.c` — TOTP per RFC 6238
- [ ] `totp_generate(secret, len, time_counter, digits)` returns token
- [ ] `totp_validate(secret, len, token, digits, step, drift_behind, drift_ahead, now)` returns bool
- [ ] Support 6–8 digit tokens
- [ ] Unit tests: RFC 6238 test vectors (SHA-1 variant)
- [ ] ≥ 80 % line coverage on `totp.c`

## Netlink Firewall Module

- [ ] Implement `netlink.c` — create/flush/delete nftables table & chain via netlink
- [ ] `netlink_init()` — create table `totpgate`, chain `input` (hook input, prio 0)
- [ ] `netlink_flush_chain()` — flush chain at startup (remove stale rules)
- [ ] `netlink_add_established_rule()` — insert `ct state established,related accept`
- [ ] `netlink_add_default_drop(target_port)` — insert `tcp dport <port> drop`
- [ ] `netlink_rule_insert(ip, port, lifetime)` — insert accepting rule with timeout
- [ ] `netlink_cleanup()` — flush chain and delete table on shutdown
- [ ] Unit tests with mock netlink socket (stub `sendto`/`recvmsg` returning canned replies)
- [ ] ≥ 80 % line coverage on `netlink.c`

## UDP Listener

- [ ] Implement `udp.c` — bind, receive, address extraction
- [ ] `udp_open(port)` — create and bind UDP socket, return fd (caller closes)
- [ ] `udp_recv(fd, buf, len, addr)` — non-blocking receive with `recvfrom`
- [ ] Handle `EAGAIN` / `EWOULDBLOCK` gracefully
- [ ] Unit tests with mock socket via socketpair or loopback
- [ ] ≥ 80 % line coverage on `udp.c`

## Auth Packet Parsing & Anti-Replay

- [ ] `auth_parse(data, len, &token, &port, &lifetime)` — parse `token[:port[:lifetime]]`
- [ ] `auth_validate(secret, cfg, token, seq, src_ip, now)` — TOTP check + seq check
- [ ] `auth_seen_before(seq, src_ip)` / `auth_record_seq(seq, src_ip)` — anti-replay table
- [ ] Unit tests: valid/invalid packets, replay detection, clock drift
- [ ] ≥ 80 % line coverage on `auth.c`

## Daemon Main Loop

- [ ] Wire up `main.c`: parse CLI → netlink_init → flush chain → add permanent rules →
      UDP bind → privilege drop → poll loop
- [ ] Signal handling: `SIGTERM`, `SIGINT` → graceful shutdown (cleanup rules, close sockets)
- [ ] Logging: `LOG_ERR`, `LOG_WARNING`, `LOG_INFO`, `LOG_DEBUG` via `syslog` (or `stderr` in foreground)
- [ ] `--foreground` flag: log to stderr instead of syslog
- [ ] Poll loop: `poll()` on UDP socket with configurable interval (for session pruning)
- [ ] Session pruning: remove expired entries from session table
- [ ] ≥ 80 % line coverage on `main.c` (excluding option parsing that calls `exit`)

## Client Tool

- [ ] Implement `src/client.c` — sends a single UDP datagram with TOTP
- [ ] `totpgate --secret <secret> --port <port> <server> [target_port]`
- [ ] Generate TOTP locally using the same `totp.c` code
- [ ] Parse server address (hostname resolution with `getaddrinfo`)
- [ ] ≥ 80 % line coverage on `client.c` (excluding `main` that calls `exit`)

## Documentation

- [ ] `README.md` — project overview, build, usage, architecture
- [ ] `AGENTS.md` — agent / AI guidelines (this file must be kept current)
- [ ] `DOMAIN.md` — business rules & entities (this file must be kept current)
- [ ] `BUG_PREVENTION.md` — recurring bug checklist (populated as bugs are found)
- [ ] `LICENSE` file (MIT)
- [ ] Man pages: `totpgated.1`, `totpgate.1`

## Hardening & Audit

- [ ] Privilege drop: `setuid`/`setgid` + `capng_clear` / `prctl(PR_CAP_AMBIENT)`
- [ ] Seccomp filter: allow only `read`, `write`, `recvfrom`, `sendto`, `poll`,
      `clock_gettime`, `getrandom`, `exit_group`
- [ ] Configuration file permissions check: warn if world-readable
- [ ] `select`/`poll` fd limit safety
- [ ] Reject overlong auth packets (> 256 bytes)
- [ ] Stack canary test (compile with `-fstack-protector-strong`)
- [ ] `-D_FORTIFY_SOURCE=2` compile flag
