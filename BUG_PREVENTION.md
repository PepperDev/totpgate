# Bug Prevention Plan / Quality Assurance

> When a bug is fixed with **medium** or **high** recurrence likelihood, add a
> note or a checklist item here.  Every task's **done criteria** includes
> reviewing this file.

---

## Checklist (consult before merging any change)

- [ ] **Integer overflow**: all arithmetic on untrusted input checked for
      overflow (especially TOTP token arithmetic, timeout calculations, buffer
      lengths).
- [ ] **Buffer bounds**: every `memcpy`/`snprintf`/`strncpy` uses the
      destination buffer size; no `strcpy`, `sprintf`, `gets`.
- [ ] **Netlink message size**: netlink messages must not exceed
      `NLMSG_GOODSIZE` (usually 8192); check before sending.
- [ ] **Endianness**: IP addresses, ports, and netlink attributes are network
      byte order; convert with `htonl`/`htons`/`ntohl`/`ntohs` where
      appropriate.
- [ ] **No double-swap**: `s_addr` from `recvfrom`/`inet_addr` is already in
      network byte order.  Do NOT pass through `bs32()`/`ntohl()` a second
      time — that reverses the bytes on little-endian, producing wrong cmp
      data.
- [ ] **File descriptor leaks**: every `open`/`socket`/`accept` has a paired
      `close` on all error paths.
- [ ] **Signal safety**: only async-signal-safe functions (see `signal-safety(7)`)
      called from signal handlers — typically just `write()` to a self-pipe.
- [ ] **Replay table size**: bounded; prune old entries; prevent unbounded
      memory growth.
- [ ] **EINTR**: all blocking syscalls (`poll`, `recvfrom`, `sendto`) wrapped
      in a loop that retries on `EINTR`.
- [ ] **Base32 decode**: reject invalid characters (including `=` padding
      errors); output buffer length check.
- [ ] **Base64 decode**: reject invalid characters (RFC 4648 standard alphabet
      only); reject malformed padding; output buffer length check.
- [ ] **Hex decode**: reject non-hex characters; handle odd-length input
      safely (no out-of-bounds read).
- [ ] **Secret prefix**: recognise exactly `hex:` and `b64:` prefixes (no
      partial or case-insensitive prefix matching).

---

- [ ] **Seccomp mode constant**: `prctl(PR_SET_SECCOMP, ...)` uses `SECCOMP_MODE_*` constants, NOT `SECCOMP_SET_MODE_*`. The set-mode constants (`SECCOMP_SET_MODE_FILTER` = 1) equal `SECCOMP_MODE_STRICT` (= 1 on this system), which enables strict mode — immediate SIGSEGV.

## Past incidents

### 2026-05-28: Wrong SHA-1 round constant K[20..39]

**Bug**: `sha1.c` used `0x6ed6eba1` instead of the correct `0x6ed9eba1` for the
SHA-1 round constant K in rounds 20–39.  Caused all hashes to be incorrect.

**Root cause**: Typo when transcribing the constant from RFC 3174.

**Prevention**: Verify all cryptographic constants against the RFC before
marking the module complete.  Cross-check against `sha1sum` output for
at least the empty string and "abc" vectors.
