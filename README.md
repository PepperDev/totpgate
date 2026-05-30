# totpgate

**Single Packet Authorization via TOTP** — a lightweight port knocking daemon
that listens on UDP for a valid TOTP and, upon matching, temporarily opens a
TCP port via direct netlink firewall manipulation.

No external binaries, no shared libraries — just a statically linked
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

- `musl-gcc` recommended (falls back to `cc`; any C99 compiler works)
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

### Manual installation (from source)

```sh
# Build and install
make
sudo make install

# Override prefix for staged installs (e.g. package build)
make DESTDIR=/tmp/staging install
```

`make install` copies the binaries and man pages to the standard paths
and applies `cap_net_admin,cap_net_raw+ep` to the daemon binary (if
run as root and `setcap` is available).  This lets the daemon manipulate
nftables rules without running as root — it drops to an unprivileged
user after binding the UDP socket.  Without capabilities you must run
`totpgated` as root.

The `setcap` step is recommended. It lets the daemon manipulate nftables
rules without running as root — it drops to an unprivileged user after
binding the UDP socket.  Without it you must run `totpgated` as root.

Pre-built binaries for multiple architectures are available on the
[releases page](https://github.com/PepperDev/totpgate/releases).

### Coverage gate

```sh
make coverage
```

All TODO sections require **≥ 80 % line coverage** and **zero compiler
warnings** before the section is considered complete.

---

## Usage

```sh
totpgated --port 2222 --target-port 22 --secret "JBSWY3DPEHPK3PXP" --timeout 30
totpgated --port 2222 --target-port 22 --secret-file /etc/totpgate.key --foreground
totpgated --port 0.0.0.0:2222 --port 192.168.1.1:2223 --interface eth0 --secret "JBSWY3DPEHPK3PXP"
totpgate  --secret "hex:48656c6c6f" --port 2222 server.example.com
```

The daemon listens on UDP `--port` for a valid TOTP.  On match the
sender's IP is allowed to open a TCP connection to `--target-port` for `--timeout` seconds.
`--port` may be given multiple times to listen on different addresses/ports,
and `--interface` restricts firewall rules to a single network interface.

When `totpgated` starts it flushes any stale rules from a prior session,
inserts a permanent `ct state established,related accept` rule, and installs
a silent `tcp dport <target-port> drop` for unmatched SYN packets.

See the man pages (`totpgated.1`, `totpgate.1`) or `--help` for full options.

---

## Project map

```
├── AGENTS.md        — agent / AI guidelines
├── DOMAIN.md        — business rules & entities
├── TODO.md          — tracked task list
├── BUG_PREVENTION.md— recurring-bug checklist
├── Makefile
├── src/             — source code
│   ├── main.c       — daemon entrypoint, event loop, CLI parsing
│   ├── client.c / h — CLI client tool
│   ├── auth.c / .h  — auth packet parse / build
│   ├── encode.c / h — base32, base64, hex decode
│   ├── totp.c / .h  — TOTP token validation
│   ├── sha1.c / .h  — SHA-1 hash
│   ├── hmac.c / .h  — HMAC-SHA1
│   ├── netlink.c / h— nftables rule management via netlink
│   ├── udp.c / .h   — UDP socket bind / send / recv
│   ├── privdrop.c/h— privilege drop & seccomp filter
│   ├── ratelimit.c/h— per-IP rate limiting with backoff
│   ├── seccomp.c / h— seccomp-BPF syscall filter
│   └── util.c / .h  — logging helpers
├── test/            — unit tests (no third-party test libs)
└── bin/             — build artifacts
```

---

## License

MIT
