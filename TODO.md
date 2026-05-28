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

- [x] Privilege drop: `setuid`/`setgid` + `prctl(PR_SET_NO_NEW_PRIVS)`
- [x] Seccomp filter: allowlist of glibc-compatible syscalls via BPF
- [x] Configuration file permissions check: warn if world-readable (via --secret-file)
- [ ] `epoll` fd limit safety (`maxevents` not exceeding `RLIMIT_NOFILE`)

## CI / CD

- [ ] GitHub Actions workflow to build and produce artifacts for:
      `i686`/`x86`, `x86_64`/`amd64`, `armhf`, `armv7`, `aarch64`
