# TODO — totpgate

> A section is removed **only** when every bullet in it is complete.
> **Complete** = zero compiler warnings + ≥ 80 % line coverage + passing tests.

---

Everything is done.

---

## Do soon — capability-based execution without root

### Goal

Let `totpgated` run without `sudo`/root by granting only the needed file capabilities via `setcap cap_net_admin,cap_net_raw+ep`.  This also enables packaging that carries capabilities in `.deb`/`.rpm`.

### What works already

- `CAP_NET_ADMIN` + `CAP_NET_RAW` is enough to open the nftables netlink socket and do all rule ops.
- `CAP_NET_BIND_SERVICE` only needed if `--port < 1024`.
- `drop_privileges()` already skips `setuid`/`setgid` when not root, so `CAP_SETUID`/`CAP_SETGID` are not required.

### What needs fixing

`drop_privileges()` in `src/privdrop.c` skips entirely when non-root:

```c
if (getuid() != 0 && geteuid() != 0)
    return 0;
```

This bypasses the `prctl(PR_SET_NO_NEW_PRIVS, 1)` call too.  Without `PR_SET_NO_NEW_PRIVS`, `SECCOMP_SET_MODE_FILTER` in `install_seccomp()` silently fails (daemon continues with a warning — fine functionally, but no seccomp confinement).

**Fix**: move `prctl(PR_SET_NO_NEW_PRIVS, 1)` into its own helper that always runs regardless of uid.  Call it unconditionally after `drop_privileges()`.  This way the seccomp BPF installs correctly even under capability-based execution.

### How capabilities survive in packages

| Format | Capability support | Mechanism |
|---|---|---|
| **tarball** | Yes, opt-in | Tar does NOT preserve `security.capability` xattrs by default. Must create with `tar --xattrs --xattrs-include='security.capability'`. Without those flags, capabilities are lost. |
| **.deb** | No native support | Standard practice: `setcap` in `debian/totpgate.postinst`. The `dh_fixperms` helper in debhelper does not touch capabilities. |
| **.rpm** | Native since RPM 4.7 | `%caps(cap_net_admin,cap_net_raw=pe) %{_sbindir}/totpgated` in the spec file. Requires RPM built with libcap. Stored in RPM DB and applied on install/upgrade. |

### Rules for release tarballs

If we ship a release tarball intended for `setcap`, we have two options:

1. **Ship without capabilities embedded** (simpler): include a `post-install` step in the README instructing `setcap cap_net_admin,cap_net_raw+ep bin/totpgated`
2. **Ship with xattrs preserved**: generate the tarball via `tar --xattrs --xattrs-include='security.capability'` after running `setcap` on the binary.  Downside: the tarball is larger and the xattrs may be stripped by the download mechanism (e.g., GitHub release archives don't preserve xattrs).

**Recommendation**: option 1 — distribute a plain tarball and document the `setcap` command for the sysadmin.

### Concrete tasks

1. **Fix `privdrop.c`**: extract `prctl(PR_SET_NO_NEW_PRIVS, 1)` into a separate helper that runs unconditionally (not gated by root check), so seccomp works under capability-based execution.

2. **Tarball packaging**: add a `make dist` target that creates a release tarball *including* `security.capability` xattrs via `tar --xattrs --xattrs-include='security.capability'`.
   - The target must run `setcap` on the binary first, then tar with xattrs.
   - Also produce a companion `*-plain.tar.gz` without xattrs for users who prefer to run `setcap` themselves.
   - Include documentation in README for both paths.

3. **Debian packaging**: create `debian/totpgated.postinst` that runs `setcap cap_net_admin,cap_net_raw+ep /usr/sbin/totpgated` on install/upgrade.
   - Must gracefully handle the case where `setcap` or `libcap` is not installed.
   - Must run `setcap -r` in `prerm` on remove (not purge) to clean up.
   - Add a `debian/totpgated.postrm` that removes capabilities on purge.

4. **RPM packaging**: add `%caps(cap_net_admin,cap_net_raw=pe) %{_sbindir}/totpgated` to the spec file.
   - Wrap in `%if %{_with_caps}` (or similar conditional) so the build doesn't break on systems without libcap.
   - Add `BuildRequires: libcap-devel` when caps are enabled.

### Acceptance criteria

- [ ] `make test` passes under `setcap cap_net_admin,cap_net_raw+ep` as non-root
- [ ] `make cppcheck` passes
- [ ] seccomp actually enforced (test via a blocked-syscall probe) when under capability-based execution
- [ ] `make dist` produces working tarballs (with and without xattrs)
- [ ] `debian/totpgated.postinst` + `prerm` + `postrm` correct (dry-run via `bash -n`)
- [ ] RPM spec `%caps` directive valid (dry-run via `rpmspec --parse`)
- [ ] no new compiler warnings
- [ ] `BUG_PREVENTION.md` reviewed for relevant items

---

## Future improvements

- **systemd service + packaging**: add `totpgated.service` to `.deb`/`.rpm` so the daemon auto-starts on install
- **musl-gcc build**: eliminate glibc static-link warnings (`getpwnam`, `getaddrinfo`)
- **IPv6 support**: `netlink.c` currently handles AF_INET only
- **Config file support**: `--config /etc/totpgated.conf` as alternative to CLI flags
- **Fuzz testing**: fuzz the auth packet parser for robustness
