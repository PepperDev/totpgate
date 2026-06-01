# Quality Assurance

## Quality Gates

cppcheck, gcov, and lizard thresholds are defined in [CONTRIBUTING.md](./CONTRIBUTING.md#quality-gate).

---

## Bug Prevention

When a bug is fixed, evaluate its recurrence likelihood:

| Likelihood | Action |
|---|---|
| Low | No action |
| Medium | Add a prevention entry to §Domain-Specific Pitfalls with bug description, root cause, and prevention plan |
| High | Add a prevention entry to §Domain-Specific Pitfalls AND add a matching test case covering the bug |

Also consult the Memory Safety Checklist and Domain-Specific Pitfalls below as part of the done criteria for every new task — review applicable items before committing.

### Memory Safety Checklist

When modifying any dynamic memory allocation (malloc/calloc/realloc/free, slab pools, or any code that manipulates allocated memory), must audit for ALL of the following hazards:

**Note**: Several hazards below (data race, torn read/write, visibility, deadlock) also apply to **statically allocated fixed-size memory** that is shared among multiple threads. Any shared memory — whether malloc'd or global — must be checked for concurrent access, atomicity of multi-word writes, memory ordering, and lock ordering hazards.

| Hazard | What to look for |
|--------|-----------------|
| **Use-after-free** | Pointer read/written after free; double-free; missing NULL after free |
| **Data race** | Shared allocation accessed by both main thread and worker without ownership handoff or mutex |
| **Out-of-bounds** | Array index from user-controlled data; fd-indexed array with unbounded fd values |
| **Dangling pointer** | realloc/malloc result assigned to global without failure check freeing old data first; pointer to realloc'd array element after growth |
| **Memory corruption** | memcpy without bounds check; missing NULL check after malloc before write |
| **Write-after-read** | Swap-last compaction reading source after potential realloc invalidation |
| **Torn read/write** | Multi-word struct written non-atomically and read from another thread |
| **Visibility** | Missing memory barrier around flag set by one thread and read by another |
| **ABA** | Lock-free freelist reuse with pointer comparison as identity |
| **Deadlock** | Multiple mutexes acquired in different order; mutex held across blocking call |
| **Init-ordering dependency** | Registration/add function called before object fields are fully initialized. Three variants: **(a)** function validates a precondition (e.g. `used` flag) that isn't set yet and silently returns; caller has no way to detect the registration was skipped; failure manifests as a later lookup miss. **(b)** guard condition involves only zero-initialized fields (e.g. `(used+tombs)*2 > cap` on globals: `0 > 0` → **false**) so a required init step (grow, allocate) is skipped, leading to NULL-pointer deref. Generic defense for any new hash table: always add `!ht \|\|` to the grow trigger — `if (!ht \|\| (used+tombs)*2 > cap) grow();` **(c) zero-init ambiguity**: sentinel value is 0 (same as calloc/memset zero state), so a guard like `if (idx >= 0)` thinks a zero-initialized field is legitimately set, causing incorrect side effects (e.g. `pend_free_buf` frees slab index 0 that was never allocated). Defense: use only negative sentinels for "not set" (-1, -2) instead of 0. |
| **Stale buffer data** | Static/reused scratch buffer not cleared between calls; leftover bytes from previous operation contaminate checksums, padding bytes, or length-dependent computations (e.g. odd-length UDP checksum reads padding byte from stale data) |
| **Realloc ordering** | Multiple realloc calls in one success-check — if earlier succeeds and later fails, earlier allocation's old block is already freed, leaving dangling global |

### Domain-Specific Pitfalls

#### Pre-Merge Safety Checklist

Before merging any change, verify these items:

- [ ] **Integer overflow**: all arithmetic on untrusted input checked for overflow (buffer sizes, timeout calculations, token arithmetic, etc.)
- [ ] **Buffer bounds**: every `memcpy`/`snprintf`/`strncpy` uses the destination buffer size; no `strcpy`, `sprintf`, `gets`
- [ ] **Netlink message size**: netlink messages must not exceed `NLMSG_GOODSIZE` (usually 8192); check before sending
- [ ] **Endianness**: network byte-order fields converted with `htonl`/`htons`/`ntohl`/`ntohs` as appropriate; avoid double-conversion (e.g. `s_addr` from `recvfrom` is already NBO)
- [ ] **File descriptor leaks**: every `open`/`socket`/`accept` has a paired `close` on all error paths
- [ ] **Signal safety**: only async-signal-safe functions (see `signal-safety(7)`) called from signal handlers — typically just `write()` to a self-pipe
- [ ] **EINTR**: all blocking syscalls (`poll`, `recvfrom`, `sendto`, `accept`) wrapped in a loop that retries on `EINTR`
- [ ] **Decode safety**: reject invalid characters in Base32/Base64/Hex input; validate output buffer length before writing
- [ ] **Secret prefix**: recognise exactly `hex:` and `b64:` prefixes (no partial or case-insensitive prefix matching)
- [ ] **Seccomp mode constant**: `prctl(PR_SET_SECCOMP, ...)` uses `SECCOMP_MODE_FILTER`, NOT `SECCOMP_SET_MODE_FILTER`. The set-mode constants equal `SECCOMP_MODE_STRICT` (= 1 on some systems), which enables strict mode — immediate SIGSEGV
- [ ] **IPv4-mapped IPv6**: the daemon binds separate AF_INET and AF_INET6 sockets by default to avoid IPv4-mapped IPv6 addresses. If still encountered, `normalize_src()` converts to AF_INET before passing to `netlink_rule_insert`
- [ ] **Client IPv6 parsing**: `parse_host_port` must handle bracketed `[ipv6]:port`, bare `ipv6` (no port), and `ipv4:port` formats. Presence of multiple colons (`memchr`) distinguishes bare IPv6 from `host:port`. `parse_server_arg` strips brackets before copying
- [ ] **Replay table size**: bounded; prune old entries; prevent unbounded memory growth
- [ ] **Revectored init**: guard conditions on zero-initialized globals may evaluate `0 > 0` as false, skipping required setup — always add `!ptr ||` to grow triggers
- [ ] **Hash table probe budget**: every open-addressing find/remove/add loop has a bounded probe budget to prevent livelock
- [ ] **Dynamic array stale pointers**: pointer to realloc'd array element stored across a potential realloc — store index instead
- [ ] **Grow-forgot-cap**: after malloc/realloc for a hash table or dynamic array, set `cap = new_cap` immediately, before any mask/budget computation

#### Generic bug patterns with code examples

##### Event-loop fairness

Every event handler that drains an fd in a `for(;;)` loop must yield back to the main event loop after a bounded number of iterations. Without a budget, a flood of events on one fd can starve all other event sources (timers, other fds, signal handlers).

```c
// WRONG — unbounded drain
static void handle_fd(void)
{
    for (;;) {
        int n = read(fd, buf, sizeof(buf));
        if (n <= 0) return;
        process(buf, n);
    }
}

// RIGHT — bounded iteration budget
static void handle_fd(void)
{
    int budget = 64;
    for (;;) {
        int n = read(fd, buf, sizeof(buf));
        if (n <= 0) return;
        process(buf, n);
        if (--budget == 0) return;   // yield to main loop
    }
}
```

Check every `for(;;)` / `while(1)` that reads from a non-blocking fd; budget 32–128.

##### Resource teardown on error paths

In manual-cleanup code, every early `return` after a successful allocation is a potential leak. Free in reverse allocation order and NULL-out after free.

```c
    conn = alloc_conn();
    if (!conn) return -1;
    job = alloc_job();
    if (!job) { free_conn(conn); return -1; }
    if (register(conn, job) < 0) {
        free_job(job);
        free_conn(conn);
        return -1;
    }
```

Check every error path clears all resources allocated so far, in reverse order.

##### Init-ordering gotchas

Zero-initialized hash tables and dynamic arrays are vulnerable to guard conditions that silently skip init:

```c
// WRONG — (used+tombs)*2 > cap → 0 > 0 → false, grow never called
if ((used+tombs)*2 > cap) grow(ht);

// RIGHT — always guard NULL first
if (!ht || (used+tombs)*2 > cap) grow(ht);
```

Also avoid sentinel value 0 when 0 is also a valid index — use -1 or -2 for "not set".

#### Entry template (for project-specific entries)

```markdown
### <subsystem>: <bug pattern title>

<context — what makes this domain tricky>

Common mistakes:
- <mistake 1>
- <mistake 2>

When modifying <subsystem>, check:
- <checklist item 1>
- <checklist item 2>

Correct pattern:
```c
// example code
```

Areas that commonly produce project-specific entries:
- **State machines**: protocol handshakes, sequence tracking, ordering constraints — desync is silent
- **Variable-length encoding**: TLV or dispatch-by-type parsers — always validate remaining buffer length against declared length before reading
- **Cross-resource lifecycle**: paired acquire-use-release across subsystems — verify cleanup on ALL error paths

---

## Code Quality Exceptions

The following functions are permitted to exceed lizard thresholds for legitimate reasons:

| Function | File | Threshold exceeded | Justification |
|---|---|---|---|
| `process_block` | `src/sha1.c` | Nesting depth (4 > 3) | SHA-1 compression loop with 4-round if/else chain — algorithmic, not accidental complexity |
| `rule_prune` | `src/main.c` | Nesting depth (4 > 3), NLOC=84 > 40 | Flush+recreate loop iterates rules twice — flat structure intentional for readability; NLOC=4 from two pass loops with expiry checks |

New exceptions must be reviewed and justified here before adding to `make lizard`'s suppression logic.

---

## Past Incidents

### 2026-05-29: Ephemeral rule timeout not enforced

**Bug**: `daemon_process()` called `netlink_rule_insert()` and logged the returned handle but never stored it.  The `lifetime` parsed from the auth packet was also ignored.  Rules persisted until daemon restart.

**Root cause**: No data structure tracked dynamic rule handles with their expiry times; the prune path only handled the replay table.

**Prevention**: Any new "insert then later delete" feature must include a tracking array and a prune callback wired into the event loop's periodic maintenance path (see `rule_track()` / `rule_prune()` in `main.c`).

### 2026-05-28: Wrong SHA-1 round constant K[20..39]

**Bug**: `sha1.c` used `0x6ed6eba1` instead of the correct `0x6ed9eba1` for the SHA-1 round constant K in rounds 20–39.  Caused all hashes to be incorrect.

**Root cause**: Typo when transcribing the constant from RFC 3174.

**Prevention**: Verify all cryptographic constants against the RFC before marking the module complete.  Cross-check against `sha1sum` output for at least the empty string and "abc" vectors.
