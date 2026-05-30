# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

## Robustness

- [x] **Firewall cleanup on graceful exit**: catch SIGINT and delete the
  totpgate table (or at least the default-drop rule and any dynamic rules)
  so no stale firewall state remains if the daemon restarts.

- [ ] **Fallback when nobody/nogroup not found**: if `getpwnam("nobody")` or
  `getgrnam("nogroup")` fails, try numeric uid/gid (e.g. 65534) before
  giving up.

- [ ] **Skip privilege drop when already unprivileged**: if the process is
  already running as non-root (uid != 0 && euid != 0), `drop_privileges()`
  should be a no-op instead of requiring the user/group to exist in
  passwd/group databases.

---

## Future improvements

- **systemd service + packaging**: add `totpgated.service` to `.deb`/`.rpm`
- **IPv6 support**: `netlink.c` currently handles AF_INET only
- **Config file support**: `--config /etc/totpgated.conf` as alternative to CLI flags
- **Fuzz testing**: fuzz the auth packet parser for robustness
