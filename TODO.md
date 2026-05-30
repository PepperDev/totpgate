# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests + `make lizard` passes.

---

## IPv6 support

- [ ] **AF_INET6 in netlink rules**: add `NFT_FAMILY_INET6` handling alongside AF_INET in `netlink.c`
- [ ] **Dual-stack listener**: accept IPv4 and IPv6 tokens on the same UDP socket (or separate per-IP sockets)
- [ ] **Mixed address matching**: allow `--interface` rules to match both IPv4 and IPv6 source addresses

---

## Future improvements

- **systemd service + packaging**: add `totpgated.service` to `.deb`/`.rpm`
- **Config file support**: `--config /etc/totpgated.conf` as alternative to CLI flags
- **Fuzz testing**: fuzz the auth packet parser for robustness
