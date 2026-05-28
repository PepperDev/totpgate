# totpgate

**Single Packet Authorization via TOTP** — a lightweight port knocking daemon
that listens on UDP for a valid TOTP and, upon matching, temporarily opens a
TCP port via direct netlink firewall manipulation.

No external binaries, no shared libraries — just a statically linked musl
binary speaking netlink directly to the kernel.

---

## Why

Traditional port knocking sequences are predictable (fixed port order) and
replayable.  TOTP-based single-packet authorization replaces the sequence with
a time-based one-time password, making each grant unique and replay-proof.

---

## Design

```
┌──────────┐   UDP/TOTP    ┌──────────────┐   netlink    ┌──────────┐
│  client  │ ────────────→ │  totpgated   │ ───────────→ │  kernel  │
│  (CLI)   │               │  (daemon)    │              │ (nftables)│
└──────────┘               └──────────────┘              └──────────┘
```

1. **Client** sends a single UDP packet containing a TOTP value.
2. **Daemon** validates the TOTP against the configured shared secret.
3. On success the daemon inserts a temporary nftables rule that permits the
   client's IP to reach the target TCP port.
4. The rule auto-expires after a configurable idle timeout.

---

## Build

### Requirements

- `musl-gcc` (or a musl-targeting cross-compiler)
- Linux kernel headers (for `linux/netfilter.h`, `libnl`-ish macros)
- `indent` (for code-style checks)

### Commands

```sh
make          # build daemon and client
make test     # build & run unit tests
make style    # reformat source to project style
make coverage # generate coverage report (requires gcov)
make clean    # remove build artefacts
```

Output lands in `bin/`.

### Coverage gate

```sh
make coverage
```

All TODO sections require **≥ 80 % line coverage** and **zero compiler
warnings** before the section is considered complete.

---

## Usage

```sh
totpgated --control-port 2222 --port 22 --secret "JBSWY3DPEHPK3PXP"
totpgate  --secret "hex:48656c6c6f" --control-port 2222 server.example.com
```

The daemon listens on UDP `--control-port` for a valid TOTP.  On match the
sender's IP is allowed to open a TCP connection to `--port` for 30 seconds.

When `totpgated` starts it flushes any stale rules from a prior session,
inserts a permanent `ct state established,related accept` rule, and installs
a silent `tcp dport <port> drop` for unmatched SYN packets.

See the (future) man-pages or `--help` for full options.

---

## Project map

```
├── AGENTS.md        — agent / AI guidelines
├── DOMAIN.md        — business rules & entities
├── TODO.md          — tracked task list
├── BUG_PREVENTION.md— recurring-bug checklist
├── Makefile
├── src/             — source code
│   ├── main.c
│   ├── totp.c / .h
│   ├── sha1.c / .h
│   ├── hmac.c / .h
│   ├── netlink.c / .h
│   ├── udp.c / .h
│   ├── config.c / .h
│   ├── auth.c / .h
│   └── util.c / .h
├── test/            — unit tests (no third-party test libs)
└── bin/             — build artifacts
```

---

## License

MIT
