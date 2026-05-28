# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

## Documentation

- [x] `README.md` — project overview, build, usage, architecture
- [x] `AGENTS.md` — agent / AI guidelines (this file must be kept current)
- [x] `DOMAIN.md` — business rules & entities (this file must be kept current)
- [x] `BUG_PREVENTION.md` — recurring bug checklist (populated as bugs are found)
- [x] `LICENSE` file (MIT)
- [x] Man pages: `totpgated.1`, `totpgate.1`

## Hardening & Audit

- [ ] Privilege drop: `setuid`/`setgid` + `capng_clear` / `prctl(PR_CAP_AMBIENT)`
- [ ] Seccomp filter: allow only `read`, `write`, `recvfrom`, `sendto`, `epoll_wait`,
      `epoll_ctl`, `clock_gettime`, `getrandom`, `exit_group`
- [ ] Configuration file permissions check: warn if world-readable
- [ ] `epoll` fd limit safety (`maxevents` not exceeding `RLIMIT_NOFILE`)
