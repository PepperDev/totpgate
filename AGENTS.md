# AGENTS — Development Guidelines

This file governs how AI agents (including future sessions) interact with the
totpgate codebase.  **Read this first** before making any changes.

---

## 1.  Reference documents

| File | Purpose |
|---|---|
| `DOMAIN.md` | Business rules, entities, glossary |
| `TODO.md` | Task list with section-completion rules |
| `BUG_PREVENTION.md` | Checklist of recurring bugs to guard against |
| `Makefile` | Single entry point for build / test / lint |

---

## 2.  Build invariants

- **Compiler**: `musl-gcc` preferred (falls back to `cc`; any C99 compiler works).
  Static linking via `-static -flto` — no glibc dependency at runtime.
- **C standard**: `-std=c99 -pedantic -pedantic-errors`.
- **Flags**: `-O3 -Wall -Wextra -flto`.
- **Link**: `-static -flto`.
- **Dependency tracking**: `-MMD -MP` — `.d` files are generated and included.
- **Binary destination**: `bin/`.
- **Style**: `indent -linux -120 -i2 -nut` — run `make style` to auto-format.
- **Static analysis**: `cppcheck` — run `make cppcheck` before committing.
- **Code metrics**: `lizard` — run `make lizard` before committing. See rules in §9.
- **Braces**: always wrap blocks with braces, even single-line `if`/`for`/`while`/`do`.
- **No third-party libraries**: implement everything from scratch (SHA1, HMAC,
  base32, base64, hex decode, netlink helpers, test framework, …).
- **No external binaries**: manipulate firewall rules via netlink sockets
  directly — never shell out to `iptables`, `nft`, or `ip`.

---

## 3.  Coding conventions

### 3.1  General

- Write for **human comprehension**.  Prefer clear names over clever tricks.
- **Avoid code duplication**.  Extract shared logic into static helpers.
- **Lightweight**: save resources, worship performance, neat memory management.
- Apply **SOLID** principles — especially Single Responsibility and
  Dependency Inversion.
- Functions should be **agnostic**: receive arguments, process, return results.
  Avoid global / file-scope mutable state as much as possible.
- Return `int` error codes (0 = success, negative = errno-style).
- Assert pre-conditions with `assert()` from `<assert.h>`.

### 3.2  Naming

| Element | Convention | Example |
|---|---|---|
| Functions | `snake_case` | `totp_validate` |
| Globals | `g_` prefix | `g_config` |
| Macros / enums | `UPPER_SNAKE` | `TOTP_DIGITS` |
| Types | `snake_case_t` | `totp_ctx_t` |
| File-local | `static` | |

### 3.3  Error handling

- Check every syscall / function return.
- On failure, set `errno` and return negative.
- Top-level `main()` prints `strerror(errno)` before exiting.

### 3.4  Memory

- Prefer stack allocation.
- When heap is required, `calloc` + paired `free`, no `malloc`/`realloc` without
  zeroing.
- No variable-length arrays (VLAs are problematic in C99 in practice).

---

## 4.  Testing

### 4.1  Framework

There is **no third-party test library**.  The test runner lives in
`test/test_runner.c` and provides:

- `TEST_GROUP(name)` / `TEST(name)` / `END_TEST`
- `ASSERT_INT_EQ`, `ASSERT_PTR_EQ`, `ASSERT_STREQ`, `ASSERT_TRUE`,
  `ASSERT_FALSE`
- `RUN_TEST(group, name)`
- `RUN_GROUP(group)` — runs all tests in a group

### 4.2  Mocks

Mocks are **stubs** — hand-written functions in `test/mock_*.c` that replace
real implementations at link time.  The Makefile compiles either the real
module or the mock variant depending on the target.

### 4.3  Coverage gate

Every TODO section requires:

1. **Zero compiler warnings** (`-Wall -Wextra -pedantic-errors`).
2. **≥ 80 % line coverage** measured by `gcov`.

Run: `make coverage`

---

## 5.  Performance-first design

When multiple technical solutions are possible, always prefer the one that
performs better under heavy workload.  Key principles:

- **I/O multiplexing**: use `epoll` exclusively — never `poll`, `select`, or `ppoll`.
- **Non-blocking**: every socket fd must be `O_NONBLOCK`.  Never use blocking
  I/O in the daemon's main loop.
- **Batch processing**: `epoll_wait` with `d->maxevents` (derived from
  `RLIMIT_NOFILE`) and process all ready fds per call.
- **Edge-triggered for data**: use `EPOLLET` on data sockets; loop
  read/write until `EAGAIN` to avoid missing events.
- **Level-triggered for control**: signal fds use level-triggered (default)
  since each signal event must be consumed exactly once per wake-up.
- **Memory**: fixed-size pools aren't just for embedded — they prevent
  allocation jitter under load.  Prefer a pre-allocated session pool with an
  SLAB-style free list.
- **Dual-stack listening**: by default the daemon binds **two** UDP sockets —
  `0.0.0.0:2222` (AF_INET) and `[::]:2222` (AF_INET6, `IPV6_V6ONLY=1`).
  IPv4 clients arrive on the AF_INET socket with a native IPv4 address,
  avoiding IPv4-mapped IPv6 (`::ffff:x.x.x.x`) that would otherwise land on
  the `ip6` nftables family.  When a single socket is explicitly configured
  (e.g. `--port [::]:2222`), `IPV6_V6ONLY=1` prevents accidental IPv4
  overlap.

---

## 6.  Task lifecycle (TODO.md)

- Each **section** groups related tasks.
- A task is **done** when:
  - Code compiles with zero warnings.
  - Line coverage ≥ 80 %.
  - `make test` passes.
  - `make style` has been run.
  - `make cppcheck` passes.
  - `make lizard` passes (see §9 for thresholds).
  - `BUG_PREVENTION.md` has been reviewed for applicable items.
- When **all** tasks in a section are done, **delete the entire section** from
  `TODO.md`.
- **Before every commit**: run `make style` and review `TODO.md` to ensure
  completed sections have been removed and remaining items are accurate.

---

## 7.  Bug prevention

Whenever a bug is fixed, evaluate its **recurrence likelihood**:

| Likelihood | Action |
|---|---|
| Low | No action |
| Medium | Add a note to `BUG_PREVENTION.md` |
| High | Add a checklist item to `BUG_PREVENTION.md` AND add a matching test case |

Also consult `BUG_PREVENTION.md` as part of the **done criteria** for every
new task.

---

## 8.  Privilege model

- Agents (build, test, lint) run as an **unprivileged user** — no `sudo`.
- If a desired system tool is missing (e.g., `musl-gcc`, `indent`, `cppcheck`, `gcov`),
  ask the user to install it rather than failing silently.
  `lizard` is installed via pip (`sudo pip install --break-system-packages lizard`).
- The daemon itself drops privileges early after binding the UDP socket.

---

## 9.  Code quality thresholds (lizard)

`make lizard` enforces the following hard limits.  Values in parentheses are
recommended targets; exceeding the hard limit causes the build to fail.

| Metric | Hard limit | Recommended | Notes |
|---|---|---|---|
| LOC per file | 600 | 300 | Non-comment, non-blank lines of code; applies to `src/` only |
| LOC per function | 80 | 40 | Non-comment, non-blank lines per function body; applies to `src/` only |
| Cyclomatic complexity | 10 | 6 | McCabe's cyclomatic complexity per function |
| Tokens per function | 500 | 250 | Proxy for statement count via `-T token_count=` |
| Nested control structures | 3 | — | `-ENS` extension in lizard |
| Function parameter count | 5 | — | Number of formal parameters |
| Cohesion & coupling | 1 public abstraction / file | — | Code review item: one public abstraction per file, low coupling, high cohesion |

Exceptions are listed in `DOMAIN.md §6` and must be
accompanied by a justification explaining why the exception is acceptable.
