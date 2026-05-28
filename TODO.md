# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

## Auth Failure Rate Limiting

- [ ] Track per-source-IP failure count with timestamps
- [ ] On repeated failures: block IP for `--min-block` (default: 5 min)
- [ ] Exponential backoff: double block duration per repeat (min → 2× → 4× → … → `--max-block`)
- [ ] CLI args: `--min-block <seconds>` (default 300), `--max-block <seconds>` (default 86400),
      `--rate-limit <failures/window>` (default 5/60s)
- [ ] After cooldown expires: re-allow the IP (clear failure count)
- [ ] ≥ 80 % line coverage on rate-limiting module
- [ ] Update `DOMAIN.md` with rate-limiting entities and rules

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
