# AGENTS — Development Guidelines

This file governs how AI agents interact with the totpgate codebase.
**Read this first** before making any changes.

---

## Design Ethos

Minimalistic, compact, secure.  Source code should be readable and maintainable
by a single human.

## Performance-First Design

When multiple technical solutions are possible, always prefer the one that
performs better under heavy workload.  Key principles:

- **I/O multiplexing**: use `epoll` exclusively — never `poll`, `select`, or
  `ppoll`.
- **Non-blocking**: every socket fd must be `O_NONBLOCK`.  Never use blocking
  I/O in the daemon's main loop.
- **Batch processing**: `epoll_wait` with `d->maxevents` (derived from
  `RLIMIT_NOFILE`) and process all ready fds per call.
- **Edge-triggered for data**: use `EPOLLET` on data sockets; loop read/write
  until `EAGAIN` to avoid missing events.
- **Level-triggered for control**: signal fds use level-triggered (default)
  since each signal event must be consumed exactly once per wake-up.
- **Memory**: fixed-size pools aren't just for embedded — they prevent
  allocation jitter under load.  Prefer a pre-allocated session pool with an
  SLAB-style free list.
- **Dual-stack listening**: by default the daemon binds two UDP sockets —
  `0.0.0.0:2222` (AF_INET) and `[::]:2222` (AF_INET6, `IPV6_V6ONLY=1`).
  IPv4 clients arrive on the AF_INET socket with a native IPv4 address,
  avoiding IPv4-mapped IPv6 (`::ffff:x.x.x.x`) that would otherwise land on
  the `ip6` nftables family.
- **Smart dynamic allocation**: prefer stack memory, but if static allocation
  would limit performance, latency, throughput, or fail under stress, use
  smart dynamic allocation with bucket grows and shrinks.  Recommended grow:
  add `max(cap, 64)` up to a ceiling (if any).  Recommended shrink: halve when
  utilisation drops below 25 % down to a floor (usually initial value).
- **Exponential backoff**: use smart retry mechanisms with exponential backoff.

See [DOMAIN.md](./DOMAIN.md#retry-landscape) for the full retry landscape and
memory management strategies.

## Domain Reference

For business rules, entities, CLI arguments, flows, retry landscape, memory
management strategies, threading architecture, glossary, and code quality
exceptions, refer to [DOMAIN.md](./DOMAIN.md).

## Contributing

Agents must follow the same Definition of Done, TODO housekeeping, code
conventions, bug prevention, quality gate, and testing requirements as human
contributors.  See [CONTRIBUTING.md](./CONTRIBUTING.md).

All items of the Definition of Done are mandatory before every commit, with no
exceptions.  This includes the full quality gate (cppcheck, lizard,
gcov ≥ 80 %), TODO housekeeping, and all other checks listed in
CONTRIBUTING.md.  Do not commit partial work — a commit that fails any quality
gate item is not permitted.

## Constraints

- Run as an **unprivileged user** — no `sudo`.
- When a required system tool is missing (e.g. `musl-gcc`, `indent`, `cppcheck`,
  `gcov`), ask the user to install it rather than failing silently.  `lizard`
  is installed via pip (`sudo pip install --break-system-packages lizard`).
- The daemon itself drops privileges early after binding the UDP socket.

All items of the Definition of Done are mandatory before every commit, along
with all other checks listed in CONTRIBUTING.md.

## Loop Mode

Agents enter loop mode on user request only.

During context compaction, make sure to keep in the context if agent is
currently on loop mode or not.

When entering loop mode follow the steps:

1. Check for work-in-progress changes in the worktree and try to match the
   task they belong to; resume it.
2. If none, tackle the next task that makes sense.
3. File and function names need not strictly match those in TODO.md — agents
   are free to reorganize them.
4. Add multi level source directories (only `main` at `src/`, remaining grouped
   in meaningful subdirectories, e.g. `src/module/code.c`), moving files to
   group related responsibilities (SOLID).
5. Each iteration, try to reduce or avoid lizard exceptions by reorganising or
   refactoring the code.
6. Apply the Definition of Done, including TODO housekeeping.
7. Commit.
8. Loop back until the user interrupts.  For relevant missing critical technical
   details or blockers (e.g. a required system tool or permission), query the
   user.  Do not query the user to decide the next task — pick the most relevant
   one and proceed.
