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

---

## Past incidents

_(Populated as bugs are found and fixed.)_
