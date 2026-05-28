# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

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
- [ ] `udp_open(port)` — create and bind UDP socket with `O_NONBLOCK`, return fd (caller closes)
- [ ] `udp_recv(fd, buf, len, addr)` — non-blocking receive with `recvfrom` loop until `EAGAIN`
- [ ] Handle `EAGAIN` / `EWOULDBLOCK` gracefully (normal termination)
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
      UDP bind → privilege drop → epoll loop
- [ ] Signal handling: `SIGTERM`, `SIGINT` → graceful shutdown (cleanup rules, close sockets)
- [ ] Logging: `LOG_ERR`, `LOG_WARNING`, `LOG_INFO`, `LOG_DEBUG` via `syslog` (or `stderr` in foreground)
- [ ] `--foreground` flag: log to stderr instead of syslog
- [ ] Epoll loop: `epoll_wait()` (edge-triggered) on UDP socket, process all ready fds per call
- [ ] Session pruning: remove expired entries from session table during idle epoll cycles
- [ ] ≥ 80 % line coverage on `main.c` (excluding option parsing that calls `exit`)

## Client Tool

- [ ] Implement `src/client.c` — sends a single UDP datagram with TOTP
- [ ] `totpgate --secret <secret> --port <port> <server> [target_port]`
- [ ] Generate TOTP locally using the same `totp.c` code
- [ ] Parse server address (hostname resolution with `getaddrinfo`)
- [ ] ≥ 80 % line coverage on `client.c` (excluding `main` that calls `exit`)

## Documentation

- [x] `README.md` — project overview, build, usage, architecture
- [x] `AGENTS.md` — agent / AI guidelines (this file must be kept current)
- [x] `DOMAIN.md` — business rules & entities (this file must be kept current)
- [x] `BUG_PREVENTION.md` — recurring bug checklist (populated as bugs are found)
- [x] `LICENSE` file (MIT)
- [ ] Man pages: `totpgated.1`, `totpgate.1`

## Hardening & Audit

- [ ] Privilege drop: `setuid`/`setgid` + `capng_clear` / `prctl(PR_CAP_AMBIENT)`
- [ ] Seccomp filter: allow only `read`, `write`, `recvfrom`, `sendto`, `epoll_wait`,
      `epoll_ctl`, `clock_gettime`, `getrandom`, `exit_group`
- [ ] Configuration file permissions check: warn if world-readable
- [ ] `epoll` fd limit safety (`maxevents` not exceeding `RLIMIT_NOFILE`)
- [ ] Reject overlong auth packets (> 256 bytes)
- [ ] Stack canary test (compile with `-fstack-protector-strong`)
- [ ] `-D_FORTIFY_SOURCE=2` compile flag
