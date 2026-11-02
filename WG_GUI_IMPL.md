# LuckFox WireGuard Web UI implementation

## Status

Implemented in the VPN rootfs overlay. Host unit, shell-service, CLI-fixture,
BusyBox 1.36.1 HTTP integration, and browser checks have been performed.
The user reported a successful full build and flash with modules available
on 2026-10-28. Hardware smoke tests confirmed peak memory below 40 MB in the
tested workload, generally usable performance despite occasional CPU pressure,
live settings/metrics, LED control, working/scannable QR codes, backup/restore
and LAN access. The remaining stress, failure and isolation cases below have
not all been confirmed; this is not yet a fully board-qualified release.

The requirements and remaining acceptance criteria are in
[WG_GUI_PLAN.md](./WG_GUI_PLAN.md).

### Native dashboard backend (2026-11-01)

The fast-backend implementation from [WG_FAST_BACKEND_PLAN.md](./WG_FAST_BACKEND_PLAN.md)
is delivered and **native dashboard routing is permanent** following the
user-collected board results and approved cleanup. Native complete-refresh p95
was 105 ms idle and 141 ms during VPN activity, with no observed errors and
38.5 MiB minimum sampled available memory in both runs. Baseline comparison
limits and remaining qualification are recorded in the fast-backend plan.

- A local [Buildroot package](./sysdrv/tools/board/buildroot/packages/vpn-web)
  installs `/opt/vpn-web/vpn-native`. Authenticated native `GET status` and
  `GET clients` use direct procfs/sysfs, `statvfs`, and bounded Generic/Route
  Netlink. They never execute Python, `wg`, `ip`, or a shell.
- JSON-C is an explicit dependency, with unsigned 64-bit JSON numbers rather
  than double-based counter serialization. The package is built with the VPN
  ARM/uClibc compiler, PIE, stack protection, RELRO/NOW and strict warnings.
  Raw netlink avoids another library dependency; its validation and fragmented
  peer merging are covered by standalone parser/collector tests.
- ARM execution exposed a real JSON-C/uClibc `duplocale` crash during verifier
  parsing, including with an explicit C locale. The VPN defconfig now declares
  a [target compatibility patch](./sysdrv/tools/board/buildroot/patches/json-c/0001-use-existing-locale-fallback-on-uclibc.patch)
  selecting JSON-C's existing `setlocale` fallback on uClibc only. CGI processes
  are single-threaded and separate, so locale changes are not shared between
  requests. Other libcs keep the original thread-local path. The ARM fixture
  tests successful authenticated JSON parsing, not merely interpreter loading
  or a missing-storage error.
- Other routes, including public `state`, private HTML/downloads and all POST
  operations, retain Python dispatch and its bounded exclusive request gate.
  Native reads bypass that gate, not the authentication or shared VPN locks.
  Authentication is released before VPN collection; VPN locks are released
  before JSON serialization/output. Exclusive writers still return explicit
  HTTP 409 conflicts. Native collection has a two-second netlink work budget
  and a five-second collection deadline. Nonblocking response writes have a
  separate five-second output budget, without either lock; slow/disconnected
  consumers cannot retain a native CGI indefinitely. A failed partial write
  is logged and closed, not replaced by a misleading second JSON response.
- Native and Python readers share descriptor-relative, no-symlink, root-only
  authentication storage checks, the existing verifier/session formats and
  fixed 1,800-second uptime lifetime. The expiry comparison uses
  `issued <= now < issued + 1800`, avoiding subtraction rounding at the exact
  fractional-time boundary. Reads do not delete or renew sessions; cleanup
  remains in initialization and Python setup/login/logout. Corrupt timestamps,
  verifiers or inaccessible storage fail explicitly. PBKDF2 remains at
  600,000 iterations; password rules, rate limiting, session cap and cookies
  are unchanged.
- Invalid client keys, IPv4 addresses, timestamps or ambiguous peer markers
  now fail explicitly in the native implementation. Limits are 128 KiB per
  metadata/settings file, 1,024 native peers/rows, 4 KiB per settings word,
  8 KiB of cookie input and 1 MiB of serialized response. These are defensive
  implementation bounds, not a nine-client limit; the existing /24 pool is
  unchanged. Optional missing sensor values retain their nullable/unavailable
  behavior; required I/O failures are not presented as fresh data.
- Browser URLs, sequential page-aware polling, 10-second cadence, hidden-tab
  suppression, sampling, cancellation, logout and history behavior are unchanged.

#### Permanent native image wiring

[The final-overlay hook](./project/cfg/BoardConfig_IPC/luckfox-vpn-overlay-post.sh)
runs after every project overlay and installs
`/var/www/cgi-bin/vpn.cgi -> /opt/vpn-web/vpn-native`. The same hook runs inside
fakeroot during VPN rootfs ext4 population, so the backend, HTTP
configuration and web-root directories are root-owned without requiring a
privileged SDK build. The VPN image hook requires a dynamically linked host
`mkfs.ext4` (host `e2fsprogs`) and passes its absolute path to the SDK image
script. The SDK's bundled static formatter cannot observe fakeroot ownership
changes and previously produced UID/GID 1000 files, preventing HTTP startup.
The VPN board uses the source image script, avoiding stale staged copies on
firmware-only rebuilds. Other boards retain the bundled formatter by default.
The actual SDK image pipeline is covered by an ext4 inode ownership/mode regression, not just a
direct host formatter test. The
[HTTP configuration](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/etc/httpd.conf)
does not force `.cgi` files through `/bin/sh`; BusyBox executes the native
ELF directly.

[S49httpd](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/etc/init.d/S49httpd)
initializes authentication and verifies that the fixed native executable is
a regular, non-symlink, root-owned file with mode 0755 before opening the
listener. Missing or unsafe binaries stop startup; there is no fallback.
Restart the service normally when needed:

```sh
/etc/init.d/S49httpd restart
```

The backend selector, deployment-choice file, legacy shell CGI and duplicate
Python dashboard handlers/settings/metrics collectors have been removed.
Incremental image assembly removes stale selector/configuration/legacy CGI
files and replaces the old volatile CGI link. Python remains required for
startup initialization, setup/login/logout, private HTML, management, backups,
downloads and QR codes. The native controller serializes these cold requests
under its bounded request gate and executes Python directly. This cleanup does
not change credentials, sessions, client data, CLI formats or VPN configuration.
There is no runtime backend rollback; reverting requires a previous firmware
version while preserving persistent data.

#### Validation and remaining qualification

The native [contract/HTTP/image suite](./sysdrv/tools/board/buildroot/tests/test_vpn_web_native.py)
uses isolated storage, frozen counters/clocks, and the actual native netlink
implementation for BusyBox HTTP tests. Separate live-peer unit fixtures do not
stand in for those transport tests. Coverage includes 0-9 clients, large
metadata limits, exact integers, quoting, expiry, malformed/symlink/FIFO storage,
concurrent readers, writer/logout conflicts, helper-execution tracing, collection
and output deadlines, root-owned ext4 wiring, permanent native routing and
incremental removal of obsolete deployment files.

After permanent-routing cleanup, all **72 regression tests passed**, including
native BusyBox 1.36.1 transport for authentication, private HTML, dashboard,
uploads/downloads and cold-gate behavior, plus the ARM/QEMU fixture. The native
sanitizer suite passed **25 tests** (26 discovered; ARM-only intentionally
skipped), with a further focused sanitizer check for unsupported native-route
methods. The ARM package and complete firmware were rebuilt. Final-image
inspection confirmed the direct native CGI link, root-owned web/backend paths,
absence of all three obsolete deployment files and removal of duplicate Python
dashboard handlers while retaining cold-operation functions.

Before permanent-routing cleanup on 2026-11-01, all **69 regression tests passed**,
including actual BusyBox 1.36.1 native/legacy HTTP and the authenticated ARM/QEMU fixture.
The native sanitizer run passed **22 tests** (23 discovered; its ARM-only
test was intentionally skipped). The final ARM package also rebuilt successfully
against patched JSON-C. Standalone netlink tests passed under host sanitizers
and ARM/QEMU; a real read-only Route Netlink exchange returned loopback
`127.0.0.1/8` with validated sender/header port IDs. Real WireGuard Generic
Netlink was not exercised by those host tests; subsequent live-board dashboard
measurements are recorded in the fast-backend plan.

Run existing and new tests with a host BusyBox 1.36.1 supporting the VPN HTTP
features (BusyBox 1.30 is intentionally skipped):

```sh
VPN_TEST_BUSYBOX=/path/to/host/busybox python3 -m unittest discover \
  -s sysdrv/tools/board/buildroot/tests -p 'test_vpn_web*.py'
VPN_TEST_BUSYBOX=/path/to/host/busybox VPN_TEST_SANITIZERS=1 \
  python3 -m unittest discover -s sysdrv/tools/board/buildroot/tests \
  -p 'test_vpn_web_native.py'
VPN_TEST_ARM=1 python3 -m unittest discover \
  -s sysdrv/tools/board/buildroot/tests -p 'test_vpn_web_native.py'
```

The ARM fixture requires the built VPN toolchain, JSON-C staging library and
`qemu-arm`. It verifies 64-bit JSON counters and filesystem arithmetic, not
real WireGuard hardware behavior. To build a suitable host HTTP fixture, copy
the existing BusyBox 1.36.1 source to a temporary directory, run `make clean`
and `make allnoconfig`, merge
[busybox-httpd.config](./sysdrv/tools/board/buildroot/tests/busybox-httpd.config)
with Buildroot's `support/kconfig/merge_config.sh -m`, then run
`yes '' | make oldconfig` and `make`. Never rebuild the target source in place
with a host compiler.

When rebuilding an already-built JSON-C package after adding the compatibility
patch, run `json-c-dirclean` before rebuilding JSON-C and `vpn-web`; a fresh VPN
defconfig build applies the declared global patch automatically. Likewise,
re-run custom-package installation and `vpn-web-dirclean` when changing local
native sources, so Buildroot refreshes its source snapshot.

Normal SDK builds register both custom packages and refresh the VPN defconfig
even when the Buildroot tree already exists. If a previous build stopped with
`native CGI missing from assembled rootfs`, rerun the normal VPN build after
updating these scripts; do not bypass the final-overlay check or manually copy
the ELF without its target libraries. If JSON-C was already built before the
locale patch, run `json-c-dirclean` as described above before retrying.
The registration regression covers fresh and existing trees and repeated
installation. After this fix, a normal Buildroot defconfig/build selected
`vpn-web` and JSON-C, applied the locale patch, and regenerated `rootfs.tar`.
Its native ELF and runtime libraries passed the final-overlay hook and QEMU
loading in isolated storage; the authenticated ARM fixture also passed.

The image ownership fix passed eight focused image/service tests. A complete
VPN firmware-only rebuild regenerated `rootfs.img` and `sd_update.img`;
`debugfs` verified UID/GID 0:0 for all 15 checked web/backend paths and parent
directories, executable modes 0755, configuration mode 0644 and the public CGI
symlink in the final rootfs image. No board was flashed by these checks.

Standalone [netlink tests](./sysdrv/tools/board/buildroot/packages/vpn-web/src/netlink_test.c)
run with GCC ASan/UBSan and also with the ARM compiler under QEMU. No host or
prebuilt target binaries are committed.

An inherited endpoint-formatting limitation was reproduced: the image's
uClibc `getnameinfo` omits IPv6 scope identifiers, as does the existing bundled
`wg` CLI using that function. Native numeric-only formatting deliberately
matches the deployed CLI on each libc (glibc preserves scopes); this rollout
does not silently change endpoint strings or perform DNS lookups. Correcting
the shared target-libc limitation is separate from the drop-in backend.

**Remaining gates:** smoke-test the permanent-routing image's startup,
authentication, browser management/QR/history and live reader/writer behavior;
record scoped-endpoint limitations and any exceptions. Live-board idle/active
measurements meet the observed latency/memory/error goals. A matched visible-tab
legacy baseline is still needed for controlled comparison claims; neither
host/QEMU checks nor interface counters prove unaffected maximum VPN throughput.

## Delivered behavior

- Token-gated, password-only first setup; no username or Linux/SSH credential
  changes.
- Custom login using PBKDF2-HMAC-SHA256 (600,000 iterations, random 32-byte
  salt), constant-time verifier comparison, and no plaintext password storage.
  Setup passwords must be 8-32 characters and contain lowercase, uppercase,
  and numeric characters; common shipped/default strings are rejected.
- Random 256-bit opaque session IDs, root-only volatile server-side storage,
  at most eight live sessions, and a fixed 30-minute monotonic-uptime lifetime.
  Polling does not renew sessions. Setup/login share a five-attempts-per-minute
  global limit, including successful attempts.
- Host-only `HttpOnly; SameSite=Strict; Path=/` cookies. No persistent cookie
  lifetime, no browser token/password storage, and no native Basic-auth prompt.
- Explicit logout revokes the current session, expires its cookie, cancels
  requests/polling, clears sensitive display/chart/QR state, and returns to
  login. Expired/missing sessions can log out idempotently; storage errors are
  reported. Other sessions are not revoked. History restoration revalidates
  access rather than restoring an authenticated display.
  If logout cannot acquire the CGI request gate, private content is still
  cleared and navigation remains disabled. The visible "Server-side logout is
  unconfirmed" message asks the user to retry Log out; only confirmed logout
  redirects to login. This fail-closed retry state is intentional and was
  observed on hardware when another request was still running.
- Dashboard; system/settings overview; client list/add/enable/disable/remove,
  profile download and SVG QR endpoint; backup create/list/download/upload,
  restore and delete. The backup list loads when opened and after create,
  upload or delete; it does not refresh periodically and has a manual Refresh
  button. Restore reports an explicit success or failure.
- Overview counters come directly from procfs/sysfs and filesystem statistics,
  not btop. Browser sampling computes CPU utilization and `eth0`/`wg0` rates;
  charts retain at most 30 samples in memory. There is no process table,
  metrics daemon, persistent history, or configuration editor.
- One global volatile LED operation for `eth_link`, `eth_act`, and `work`.
  Enabled/disabled/mixed/unavailable describe trigger configuration, not
  instantaneous illumination. Partial failures include the resulting state.
  The shared helper never changes the MAC or cycles networking. Boot may
  re-enable the configured triggers.
- Plain HTTP bound to the current global IPv4 address on `eth0`, TCP 8080.
  Firewall rules reject non-`eth0` access. No all-interface/IPv6 listener.
  The service positions its ingress guard before broad USB/established accepts,
  even when an equivalent guard already exists lower in the chain.
  Startup retries missing storage/DHCP every five seconds without blocking
  remaining boot services; stop cancels pending initialization/retries.
  Later address changes require restarting the service.

## Architecture and source map

Paths below are relative to the repository.

| Component | Source |
|---|---|
| Root HTTP service/supervisor | [S49httpd](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/etc/init.d/S49httpd) |
| BusyBox HTTP configuration | [httpd.conf](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/etc/httpd.conf) |
| Native front controller and collectors | [native package](./sysdrv/tools/board/buildroot/packages/vpn-web/src) |
| Final permanent native image wiring | [overlay/image hook](./project/cfg/BoardConfig_IPC/luckfox-vpn-overlay-post.sh) |
| Python standard-library cold-operation backend | [webui.py](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/vpn-web/webui.py) |
| Private management HTML | [app.html](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/vpn-web/app.html) |
| Public login/setup shell and local assets | [web root](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/var/www) |
| Shared LED-only helper | [system-leds](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/usr/sbin/system-leds) |
| Startup integration, retaining work-LED initialization before missing-eth0 exit | [S39lan](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/etc/init.d/S39lan) |
| Backup CLI / retention helper | [backup.sh](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/pivpn/backup.sh), [prune-backups.py](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/pivpn/prune-backups.py) |
| Shared archive validator/extractor and restore integration | [archive.py](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/pivpn/archive.py), [restore.sh](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/pivpn/restore.sh) |
| Image features | [BusyBox fragment](./sysdrv/tools/board/buildroot/busybox-vpn.fragment), [VPN defconfig](./sysdrv/tools/board/buildroot/luckfox_pico_vpn_defconfig) |
| Automated host tests | [tests](./sysdrv/tools/board/buildroot/tests) |

### Approved implementation changes from the initial plan

The existing image already selects Python 3 and SSL. The user approved using
its standard library instead of writing form parsing, JSON, authentication,
sessions and archive handling in shell. Python starts only for cold
CGI requests: no web framework, pip package, database, or persistent application
server was added. Zlib is now explicitly selected, rather than relying on
aiohttp's indirect selection.

A single `/cgi-bin/vpn.cgi/<operation>` router replaces the planned individual
shell endpoint files. Operations/methods/fields are listed in the plan. The
authenticated `/app` route serves private HTML from outside the static root;
only the login/setup shell and nonsensitive JS/CSS are publicly served.
The public `/state` operation discloses only whether setup is required.
Direct unauthenticated management-page navigation redirects to login;
unauthenticated data/action requests return HTTP 401.

The native controller's gate serializes cold CGI operations before starting Python. It waits at
most about 0.5 seconds for the previous request to finish and otherwise returns
JSON HTTP 503 `busy`. This also absorbs the short interpreter-shutdown interval
after a completed response. CLI activity can independently return a retryable
VPN-lock conflict. Browser requests are sequential, polling runs only while
visible, and navigation changes during polling are queued.

The responsive card UI and action icons are original and use system fonts and
local assets; no reference application source or fonts were copied.
The user supplied the WireGuard PNG and confirmed permission to redistribute
and recolor it. [wireguard.png](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/var/www/wireguard.png)
is rendered as a CSS alpha mask: original red (`#88171a`) in light mode and
dashboard green (`#53dfb3`) in dark mode, with no additional bitmap or external
asset request.

### Appearance and compact client overview

Light mode is the default when no valid preference exists, including login/setup.
The Settings **Dark mode** switch and matching upper-right login/setup switch
share a small [theme.js](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/var/www/theme.js)
loaded before styles/rendering. Only `light`/`dark` is saved in browser
localStorage (`vpn-ui-theme`), not credentials or device files. The choice
survives reload, logout, session expiry and browser restarts, and synchronizes
across open tabs on the same origin. Clearing site data, another browser/profile,
or a different host/port has a separate/default preference. Blocked storage
shows a warning beside the switch while allowing temporary theme changes.
Surfaces, controls, notices, charts and logo colors all adapt to the selected
theme.

Client rows now follow the supplied compact layout: avatar/recent-handshake
dot, name/address and sampled server-side RX/TX rates; an enable/disable switch;
QR, download and delete icon buttons with accessible names/tooltips; and
expandable creation/handshake/endpoint/cumulative-counter details. The **+ New**
header button opens a client-name dialog. Existing confirmation, validation,
authentication and error-handling flows are preserved. Rates need consecutive
valid snapshots; hidden-page resumes and counter resets do not invent traffic.

The global LED control is also a switch, with explicit aggregate state.
Mixed configuration is centered/dashed and explained, with the next operation
enabling all LEDs; unavailable hardware disables the switch. Device mutations
remain server-confirmed rather than optimistic. Theme switching remains
available during polling and does not send an API mutation.

### BusyBox integration details discovered by testing

1. BusyBox 1.36.1 exports `Origin`, custom request headers and cookies to CGI.
   The WSL host's 1.30.1 does not export the required arbitrary headers, so it
   cannot validate this transport contract.
2. With CGI enabled but `FEATURE_HTTPD_BASIC_AUTH` disabled, the bundled
   1.36.1 source truncates the directory index name and restores it only in the
   Basic-auth feature block: `/` incorrectly returns 404 even though
   `/index.html` works. The VPN fragment now enables the feature to fix index
   serving. No Basic-auth rules are configured; password-only form login and
   CGI sessions remain the authentication model. Root-page serving is covered
   by a real HTTP regression test.
3. BusyBox omits CGI `CONTENT_LENGTH` for zero-length POST requests. Fieldless
   form routes accept that representation; password/setup/upload routes still
   require an explicit usable body length.

## Backup behavior and compatibility

Backups created by this appliance's `pivpn backup` before the web UI are
supported directly: upload the original `.tgz`, then use Restore. No GUI
metadata, version marker or conversion is required. The supplied
`pivpnbackup-20261022-100716.tgz` passes the shared archive validator,
authenticated upload, listing, byte-identical download and private staged
extraction with all nine files preserved in isolated temporary state.
Both legacy GNU and ustar layouts are covered by synthetic regression tests
for upload, listing, byte-preserving download, private staged extraction and
restore-command dispatch. Tests use synthetic keys, not the supplied secrets.
These checks do not constitute a live board restore.
VPN restores leave the separately stored web UI password and sessions unchanged.
Archives must still meet the appliance and safety constraints below; this does
not add support for arbitrary upstream PiVPN installations or modified hooks.

`pivpn backup` keeps its normal human-readable behavior. Optional `--web`
returns only the created basename for the CGI adapter. Backups are built into
private temporary files, check both sides of the tar/gzip pipeline, and are
published only after success. Same-second names use an available numeric suffix
without overwriting an existing archive.

Creation retains five archives, using modification times and numeric suffixes
for ties; the just-created archive is always retained even after a clock step
backwards. Upload preserves the original
`pivpnbackup-YYYYMMDD-HHMMSS[-N].tgz` basename, provided by the browser in
`X-VPN-Backup-Name`; `N` is an optional positive numeric suffix. Paths and other
filenames are rejected. As approved after hardware testing, a same-named
archive is atomically replaced only after complete upload and validation.
Truncation, invalid archives and publication failures leave the existing backup
untouched. The listed modification time is the upload time, not the historical
timestamp in the filename. Upload does not immediately prune the list;
uploaded archives participate in retention at the next creation.

Uploads require `application/gzip`, a nonzero Content-Length of at most
16 MiB, and at least the body size plus 4 MiB free on the destination
filesystem. Transfer chunks are at most 64 KiB and incomplete files are removed.
Downloads stream an opened descriptor rather than buffering the archive in RAM.

Upload and CLI restore share validation. It accepts only the expected
WireGuard keys/configs/client metadata and fixed-appliance setup variables;
requires the essential files; and rejects:

- Links, special files, traversal/absolute/duplicate paths and unexpected files.
- PAX/GNU extension headers before buffering their payloads. Normal short-name
  GNU/ustar archives produced by the existing backup command are supported.
- Executable setup-variable syntax, unexpected variables, alternate device
  paths, WireGuard hooks and unknown configuration directives, including hooks
  hidden in disabled peer blocks.
- Invalid configuration/key/metadata shapes, corrupt/truncated gzip/tar, and
  hidden nonzero data after the tar terminator.
- More than 1,024 entries, individual files over 1 MiB, or expanded input over
  32 MiB.

Restore extracts only validated regular files into a private staging directory;
it never invokes general tar extraction on an untrusted archive. These checks
intentionally narrow compatibility to this `eth0`/`wg0`, /24 appliance.
Hand-modified archives with extra hooks/files/variables may now be rejected.
Existing replacement, wg0 restart and `/userdata/wireguard.prev` semantics
remain; `.prev` is not a full rollback of `/etc/pivpn`.

Command failures are not converted to successful empty responses. Timeouts
terminate the operation's process group, first allowing shell cleanup and then
forcing termination if necessary. A timed-out operation may have partially
changed persistent state: inspect/refresh before retrying.

## First use and recovery on the board

Build the VPN image using the repository's existing board/VPN build workflow;
deploy the overlay, BusyBox fragment and Python SSL/zlib selections together.
Do not deploy the root-running service alone over the old unauthenticated
placeholder.

After `/userdata` is mounted and the reserved LAN lease is acquired:

1. Check `/var/log/httpd.log` and the listener on the LAN address, TCP 8080.
2. Through trusted console/SSH, retrieve:

   ```sh
   cat /userdata/webui/setup-token
   ```

3. Browse to `http://192.168.0.10:8080/` (or the actual reserved IPv4 address).
   Enter the token and a unique password twice. Setup removes the token after
   verifier persistence and requires a separate login.
4. Sign in, inspect the system/client pages, and use Log out when finished.

Persistent verifier/token files are root-owned mode 0600 under
`/userdata/webui` (0700), outside VPN backups/restores. Sessions/rate-limit
state live under `/run/webui` and do not survive reboot. If setup is interrupted
after the verifier was committed, the verifier is authoritative: login is
available, another setup cannot replace it, and service initialization removes
any leftover setup token.

Lost-password recovery, through trusted console/SSH only:

```sh
/etc/init.d/S49httpd stop
# Let any already-running management operation finish before recovery.
rm -f /userdata/webui/auth.conf /userdata/webui/setup-token
/etc/init.d/S49httpd start
cat /userdata/webui/setup-token
```

Initialization invalidates old sessions before reprovisioning. Complete the
token-gated wizard again; VPN clients and Linux/SSH credentials are unchanged.
There is no browser recovery or multi-user administration.

After an unexpected LAN address change:

```sh
/etc/init.d/S49httpd restart
```

## Verification performed

**45 automated tests passed** after the upload-filename follow-up, including:

- Setup token/password validation, protected verifier permissions, persistence
  failure, disabled repeated setup and invalidation during reprovisioning.
- Cookie attributes, fixed expiry despite polling, reboot-uptime invalidation,
  bounded sessions/attempts, duplicate/path-like cookies and logout revocation,
  idempotence, other-session isolation and storage errors.
- Authentication gates, methods, origin/custom-header checks, strict/duplicate
  fields, single URL decoding and safe fixed-argv client operations.
- Down-interface configured-client visibility, non-secret JSON, exact profile
  bytes, streamed backup descriptors and partial LED-operation reporting.
- Exact 16 MiB upload threshold and <=64 KiB reads; oversized/truncated/invalid
  upload rejection and cleanup.
- Uploaded filename preservation, fresh modification times, same-name atomic
  replacement only after validation, invalid/missing filename rejection and
  existing-backup preservation on truncation/validation/publication failures.
- Valid archive extraction, link/traversal/duplicate/extension/hook/settings
  rejection, missing files, corrupt gzip and expansion bounds.
- Twelve same-second CLI backup creations with five retained archives,
  numeric tie ordering, clock rollback and tar failure despite gzip success.
- A host-built copy of the bundled BusyBox 1.36.1 running the production shell
  CGI gate/configuration: root index, setup, login, private HTML/security
  headers, status, cross-origin rejection, logout/old-cookie rejection,
  filename-header transport, byte-identical upload/download/replacement, and
  bounded HTTP 503 contention behavior. Only target storage/locks and
  unavailable host hardware are replaced by private temporary fixtures.
- Service fixtures: late DHCP recovery, repeated-start idempotence, listener
  startup after firewall setup, existing ingress-guard repositioning, and stop
  while still waiting for DHCP.

Run on a Linux host from the repository root:

```sh
python3 -B -m unittest discover \
  -s sysdrv/tools/board/buildroot/tests -p 'test_vpn_web*.py' -v
```

The HTTP tests need a host-native BusyBox with the VPN HTTP features. For
example, build the bundled 1.36.1 source natively with HTTPD, CGI,
CONFIG_WITH_SCRIPT_INTERPR and BASIC_AUTH enabled, then run:

```sh
VPN_TEST_BUSYBOX=/path/to/native/busybox python3 -B -m unittest discover \
  -s sysdrv/tools/board/buildroot/tests -p 'test_vpn_web*.py' -v
```

The known-incompatible host BusyBox 1.30 is skipped, rather than treated as a
passing HTTP test. Fixtures never modify host VPN/auth state.

Also passed shell syntax checks for changed scripts, Python AST parsing,
JavaScript `node --check`, and tracked Git whitespace checks.

Browser checks against isolated temporary state exercised setup/login,
dashboard/system metrics, empty clients/backups, navigation during polling,
390-pixel mobile layout without horizontal page overflow, and logout followed
by Back navigation with no authenticated content restored.

Appearance/client-layout follow-up checks verified light on initial load and
reload, Settings theme switching, exact green dark-logo color, compact rows
with enabled/disabled sample clients, the new-client dialog, and mobile
overflow in dark mode. Browser-side fixtures also exercised all four LED
states, mixed-to-enable targeting, visible LED failure without optimistic
success, client-disable confirmation cancellation/failure, rate sampling,
counter reset handling and literal rendering of HTML-like client names.
Theme persistence supersedes the earlier reset-on-reload behavior. A focused
Node test checks default/invalid values, persistence across page instances,
application before DOMContentLoaded, tab synchronization and blocked storage:
`node sysdrv/tools/board/buildroot/tests/test_vpn_theme.js`.
The original 45 backend/HTTP/service tests passed after the UI changes.
The upload-filename follow-up was also checked in the browser JavaScript
runtime: the upload handler sends the original filename header, preserves the
raw File body and rejects invalid filenames before sending a request.
Sample client names used for visual feedback live only in temporary preview
state and are not installed into the firmware.

## Hardware validation reported on 2026-10-28

- Full build and flash completed; modules are available.
- Peak memory was below 40 MB in the tested workload. CPU was occasionally
  stretched, but the GUI generally worked well.
- Live settings and metrics, LED control, QR generation/scanning,
  backup/restore and LAN access worked.
- Logout occasionally reached the intentional unconfirmed/retry state;
  retrying Log out succeeded.
- Backup upload renamed archives to the current time. The follow-up fix
  preserves uploaded basenames and validates before same-name replacement.
  This follow-up still needs deployment and confirmation on the board.

## Remaining board acceptance before release

- Verify final image size/overlay ownership/executable modes and detailed
  BusyBox/Python SSL/zlib/module coverage beyond the reported availability.
- Extend peak RAM and latency measurements on the 64 MiB board: startup, login,
  visible/hidden polling, concurrent browsers, SVG generation, maximum uploads,
  and restore (which runs the CLI/validator alongside the CGI process).
  CGI serialization limits concurrency but is not a substitute for this test.
- Check thermal/memory/CPU/storage edge cases, network counter resets and
  wg0 stopped/running behavior beyond the reported live metrics/settings.
- Extend LED testing to mixed/missing/partial-write states,
  network continuity when toggling, and reboot re-enablement.
- Verify exact downloads and client operations against actual WireGuard state.
- Extend backup/restore testing on disposable board state to active peers,
  disk-full/write failure, malformed uploads and `.prev` recovery limitations.
- Confirm rejection from USB-RNDIS, WAN and IPv6, including after boot with
  late DHCP and after service restart.
- Confirm final kernel time/randomness, token retrieval, session expiry,
  logout, recovery and no secret-bearing logs/caches.

Plain HTTP exposes passwords, cookies and VPN secrets to LAN observers.
Root-running CGI means a backend compromise can compromise the device.
Neither LAN binding nor password authentication changes those accepted risks.
