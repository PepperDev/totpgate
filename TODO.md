# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests + `make lizard` passes.

---

## Future improvements

- **systemd service + packaging**: add `totpgated.service` to `.deb`/`.rpm`
- **Config file support**: `--config /etc/totpgated.conf` as alternative to CLI flags
- **Client-only build for macOS/Windows**: produce standalone `totpgate` CLI binary (no daemon, no netlink) for generating TOTP codes on non-Linux platforms
- **Fuzz testing**: fuzz the auth packet parser for robustness
