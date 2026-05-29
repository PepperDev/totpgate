# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

Everything is done.

---

## Future improvements

- **systemd service + packaging**: add `totpgated.service` to `.deb`/`.rpm` so the daemon auto-starts on install
- **musl-gcc build**: eliminate glibc static-link warnings (`getpwnam`, `getaddrinfo`)
- **IPv6 support**: `netlink.c` currently handles AF_INET only
- **Config file support**: `--config /etc/totpgated.conf` as alternative to CLI flags
- **Fuzz testing**: fuzz the auth packet parser for robustness
- **CLI `--interface`**: add argument to specify network interface for firewall rules (source IP binding)
- **Multi-port `--port`**: allow `--port` to be given multiple times, with optional IP binding in `[ip:]port` format (e.g. `0.0.0.0:2222`, `[::]:2222`, or an interface's IP)
