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
  restore and delete.
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
| Small shell entry point / request gate | [vpn.cgi](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/var/www/cgi-bin/vpn.cgi) |
| Python standard-library backend | [webui.py](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/vpn-web/webui.py) |
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
sessions and archive handling in shell. Python starts only for each CGI
request: no web framework, pip package, database, or persistent application
server was added. Zlib is now explicitly selected, rather than relying on
aiohttp's indirect selection.

A single `/cgi-bin/vpn.cgi/<operation>` router replaces the planned individual
shell endpoint files. Operations/methods/fields are listed in the plan. The
authenticated `/app` route serves private HTML from outside the static root;
only the login/setup shell and nonsensitive JS/CSS are publicly served.
The public `/state` operation discloses only whether setup is required.
Direct unauthenticated management-page navigation redirects to login;
unauthenticated data/action requests return HTTP 401.

The shell gate serializes CGI execution before starting Python. It waits at
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
The current 45 backend/HTTP/service tests pass after the UI changes.
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
