# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

## Packaging (capability-based execution)

- [ ] **`make dist` target**: create a release tarball with
  `security.capability` xattrs embedded.  Requires `setcap` on the binary
  first, then `tar --xattrs --xattrs-include='security.capability'`.
  Document the manual `setcap` command in README for users who build from
  source.

- [ ] **Debian packaging**: create `debian/totpgated.postinst` that runs
  `setcap cap_net_admin,cap_net_raw+ep /usr/sbin/totpgated` on install/upgrade.
  Must handle missing `setcap` gracefully.  Add `prerm` (remove) and `postrm`
  (purge) scripts.

- [ ] **RPM packaging**: add `%caps(cap_net_admin,cap_net_raw=pe) %{_sbindir}/totpgated`
  to the spec file, wrapped in `%if %{_with_caps}`.  Add `BuildRequires:
  libcap-devel` when caps are enabled.

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
