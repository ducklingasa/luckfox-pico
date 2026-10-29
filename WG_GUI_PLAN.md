# LuckFox WireGuard Web UI Plan

Implementation status and deployment/verification instructions are recorded in
[WG_GUI_IMPL.md](./WG_GUI_IMPL.md). The implementation uses the existing image's
Python 3 standard library for short-lived CGI requests, as approved during
implementation; it does not introduce a persistent Python server.

## 1. Goal and scope

Add a small browser-based management UI for the existing LuckFox Pico Mini A
WireGuard server. The UI is a presentation layer over the deployed shell tools;
it is not a replacement VPN implementation and must not edit WireGuard files
independently of the existing management commands.

The first release covers:

- Server/interface status and client traffic status.
- A system overview/settings page with critical resource metrics and one
  global enable/disable control for all Ethernet and onboard work LEDs.
- Client listing, creation, enable/disable, removal, configuration download,
  and QR display.
- Backup creation, listing, download, browser upload, and restore.

The first release is accessed directly over HTTP on the trusted home LAN. It
does **not** provide arbitrary WireGuard/firewall editing, SSH administration,
multi-user roles, or internet/WAN access to the UI. It includes a first-boot
wizard to set the UI's single web-admin password only; it does not create or modify
Linux users, the root password, SSH keys, or WireGuard clients.

Plain HTTP is not encrypted: anyone able to observe the home LAN can capture
login credentials, client profiles, QR payloads, and backups. This trade-off is
accepted only for a private, trusted home LAN. Do not use the UI on public,
guest, or otherwise untrusted Wi-Fi; do not expose it through router port
forwarding; and do not treat the password as protection against LAN
eavesdropping. If encrypted transport is required, this direct-HTTP design is
not sufficient and must be replaced by HTTPS or a secure tunnel.

## 2. Existing implementation: source of truth

Use the current server implementation documented in
[VPN_SERVER_IMPL.md](./VPN_SERVER_IMPL.md), not the earlier design assumptions
in isolation.

| Area | Existing behavior the UI must preserve |
|---|---|
| Server | `wg0`, UDP 51820, server address `10.6.0.1/24`; server and peer configuration live under `/userdata/wireguard`. |
| Client address pool | `10.6.0.2` through `10.6.0.254`; `pivpn add` selects the lowest unused address. |
| Client profiles | Full tunnel (`0.0.0.0/0, ::/0`), Quad9 DNS, MTU 1420, keepalive 25 seconds, endpoint `psykey.webhop.me:51820`. |
| Client identity | Profiles and private/preshared keys are stored under `/userdata/wireguard`; a downloaded profile or QR code is a credential. |
| Management | `/usr/sbin/pivpn` dispatches to `/opt/pivpn/*.sh`. Changes use `/run/pivpn.lock`, update persistent files, and apply them with `wg syncconf` when `wg0` is running. |
| Client names | Must match `[A-Za-z0-9][A-Za-z0-9._-]{0,14}`; unique. |
| Client actions | `pivpn remove`, `pivpn on`, and `pivpn off` accept multiple names. The web UI sends one name per action and supplies `-y` only after the user confirms in the UI. |
| Disabled clients | A disabled peer is retained in `wg0.conf` with a `#[disabled] ` marker. It is not deleted and can be enabled again. |
| Live status | `pivpn clients` needs a running WireGuard interface. Its RX/TX counters are runtime counters, not lifetime totals and not persistent history. |
| Backups | `pivpn backup` archives `/userdata/wireguard` and `/etc/pivpn`, retains the newest five archives, and creates an unencrypted archive containing secrets. |
| Restore | `pivpn restore <file> -y` accepts the existing backup format, replaces server/client keys and settings, takes `wg0` down/up, and retains the prior WireGuard directory as `/userdata/wireguard.prev`. |

Never scrape the ANSI-formatted output of `pivpn list` or `pivpn clients` as an
API. Read endpoints need a stable, non-secret structured data path; mutating
endpoints should invoke the existing `pivpn` command with fixed, quoted
arguments. If the CLI output or data format must change to support the UI, keep
the CLI behavior backward-compatible.

## 3. First-boot account wizard

### First-boot UI account flow

```text
First boot with /userdata mounted
        ↓
Generate one-time setup token; no UI account verifier exists
        ↓
Operator retrieves token through trusted console or existing SSH
        ↓
Browser shows setup wizard only; operator sets UI password (no username)
        ↓
Verify token and password; atomically store verifier and consume token
        ↓
Redirect to login; all management pages and APIs require the UI account
```

- The wizard provisions one password-only web-admin identity, with no username
  field. Its password must not be reused as Linux or WireGuard credentials by
  the system; do not attempt to
  synchronize them with root or SSH.
- Require a strong password entered twice. Set and
  document a minimum password length appropriate to the chosen authentication
  mechanism; reject known defaults and never echo the password back.
- Keep the one-time token outside the browser until the operator enters it.
  Store it only in `/userdata/webui/setup-token` beneath a root-owned
  mode-`0700` `/userdata/webui` directory; compare it safely, rate-limit
  failures, and remove it only after verifier persistence succeeds. If
  persistence fails, do not show successful setup or strand the device in an
  ambiguous partially configured state.
- Generate token material only after the kernel CSPRNG is ready. If secure
  randomness or `/userdata` is unavailable, fail closed and do not enable the
  wizard or create a predictable fallback token.
- After account setup, the wizard route must stop accepting setup requests and
  redirect to login. There is no multi-user support or browser reset flow.
- Store the account verifier at `/userdata/webui/auth.conf`, not under
  `/userdata/wireguard`: the existing VPN backup archives the entire
  WireGuard-data directory, so this separation prevents the UI password
  verifier and setup token from being included in VPN backups or replaced by a
  VPN restore. Protect the directory and files with root ownership and
  restrictive permissions.

### Login and account recovery

- After setup, present a custom login page with only a password field, not a
  browser-native HTTP Basic prompt. Successful login issues a short-lived,
  opaque session cookie; subsequent requests do not resend the password.
- Use a cryptographically random session identifier with server-side state
  under a root-owned mode-`0700` directory in `/run`; session files are mode
  `0600`. Sessions do not survive reboot. Bound concurrent session count,
  expire sessions server-side using monotonic uptime, and clean up expired
  state. Use a fixed 30-minute lifetime from login, not a sliding lifetime
  extended by automatic status polling.
- Set a host-only cookie with `HttpOnly`, `SameSite=Strict`, and `Path=/`;
  omit `Domain` and persistent `Expires`/`Max-Age` attributes. Plain HTTP cannot
  provide a working `Secure` cookie; session theft remains a trusted-LAN risk.
  Never place session identifiers in URLs, logs, or browser storage.
- Require a valid session for all management pages and CGI endpoints, except
  the public login/setup shells and their narrowly scoped handlers. Expired
  API requests return HTTP 401; the browser clears displayed secrets and
  returns to login without automatically replaying a mutation. Logout accepts
  an absent or expired session as described below; it grants no access.
- Provide a Logout button on every authenticated page. Send a same-origin
  `POST` to invalidate the current server-side session and clear its cookie
  with the same name/path, no `Domain`, and `Max-Age=0`. Logout affects only
  that browser session, not other sessions or the web-admin password.
  Make it idempotent: absent or expired sessions still clear the cookie and
  succeed, but a session-storage failure must be reported rather than claiming
  revocation succeeded. Stop polling, discard in-flight responses, clear
  displayed secrets and in-memory chart data, and return to login. On failure,
  clear sensitive display state but show that server-side logout is unconfirmed.
  Protect management HTML with `Cache-Control: no-store`; on history/back
  restoration, clear sensitive state and revalidate the session before
  displaying management data.
- For a lost password, use the documented local console/SSH recovery
  procedure: stop or restrict the web service, remove the existing verifier,
  generate a fresh one-time setup token at the protected path, then complete
  the wizard again.
  Existing VPN clients and root/SSH credentials are not changed by this flow.

### Web pages

- **Dashboard:** server/interface status, recent clients, and traffic counters.
- **System overview / Settings:** critical resource metrics, read-only
  WireGuard settings, and one runtime global LED control.
- **Clients:** list, add, enable/disable, remove, download profile, and display
  QR code.
- **Backup:** create, list, download, upload, and restore backups.

The detailed behavior for these pages is specified in section 6.

## 4. Runtime architecture

```text
Administrator's browser on the trusted home LAN
        │ HTTP + web-admin authentication
        ▼
192.168.0.10:8080 — BusyBox httpd (LAN only)
        ├── static HTML/CSS/vanilla JavaScript
        └── one shell CGI entry point → Python 3 standard-library router
                 ├── read-only status/client helpers
                 └── /usr/sbin/pivpn for changes
                           └── existing scripts, lock and WireGuard tools
```

- Serve static files from the existing `/var/www` web root; place CGI
  programs in its CGI directory. Do not put keys, profiles, backups, or
  generated state in the web root.
- Use `/cgi-bin/vpn.cgi/<operation>` with `PATH_INFO` dispatch, rather than a
  separate script per operation. Keep private management HTML and backend
  modules under `/opt/vpn-web`, outside the static root. Serialize CGI
  execution with a bounded 0.5-second request-lock wait before starting Python;
  web requests still busy afterward receive a retryable HTTP 503 rather than spawning multiple
  memory-heavy interpreters. CLI commands retain their independent VPN lock.
- Use BusyBox `httpd` and CGI only if the BusyBox applet in the selected
  Buildroot image supports the required LAN bind address, CGI execution,
  request-cookie access, and response headers including `Set-Cookie`.
  Authentication is handled by the shared CGI guard, not native HTTP Basic.
  Verify those exact capabilities on the
  target image before implementation. Add an init script with a unique
  sequence after `S41dhcpcd` and `S48wireguard`; confirm the final init ordering
  rather than assuming a sequence number is unused.
- BusyBox 1.36.1 has a directory-index restoration bug when CGI is enabled
  without `FEATURE_HTTPD_BASIC_AUTH`. Enable that feature for correct `/`
  serving, but configure no native Basic-auth rules; the custom form/session
  guard remains the sole web authentication mechanism. Older host BusyBox
  1.30 does not export the required arbitrary CGI headers and is not a suitable
  transport-validation substitute.
- Browse directly to `http://192.168.0.10:8080` from a device on the trusted
  home LAN. The board keeps its DHCP reservation; this is not a static-address
  change in the rootfs.
- Rely on that stable reservation: after DHCP startup, bind to the assigned
  global IPv4 address on `eth0`. If no address is initially available, keep
  retrying at a bounded interval without opening an all-interface listener;
  start only one listener when the address arrives. Stop must cancel pending
  retries. Unexpected later address changes require a service restart;
  automatic address-change monitoring/rebinding is out of scope.
- Bind only to the LAN IPv4 address `192.168.0.10` if the selected BusyBox
  `httpd` supports it. Otherwise, bind as required by the applet and enforce
  equivalent interface/source restrictions in the firewall before enabling the
  service. Do not listen on a public/WAN address or IPv6. The current firewall
  accepts all traffic on `usb0`, so do not assume its default-drop policy
  protects an all-interface listener; ensure the HTTP service is not exposed
  on USB-RNDIS.
- Require the dedicated password-only web-admin session for all management
  pages and CGI endpoints after setup. On first boot, when no account verifier exists, show
  only the setup wizard; do not expose dashboard, management API, profile, QR, backup, or
  mutation endpoints.
- Protect first-account creation against an unauthenticated LAN user claiming
  the account first. Generate a cryptographically random one-time setup token
  on the device and store it root-owned with mode `0600` at
  `/userdata/webui/setup-token`. The operator retrieves it through trusted
  console or existing SSH access and enters it in the wizard. Do not print it
  to general logs, include it in the HTTP page, or ship a default token.
  Consume it atomically when account setup succeeds; concurrent setup requests
  must allow only one winner.
- The wizard collects only a password entered twice, validates length and
  rejects empty/default credentials, then stores only a password verifier in a
  root-owned mode-`0600` file at `/userdata/webui/auth.conf`. Never persist or
  log the plaintext password, and never include the verifier in Git or the
  rootfs overlay. Use a supported password hashing/authentication mechanism
  available in the target Buildroot image; verify its behavior and safe
  integration with CGI before implementation rather than inventing
  cryptography. Verify secure random session identifiers, cookie handling,
  server-side expiry, and bounded login/setup rate limiting as well. If no
  suitable password-verification mechanism is available, do
  not enable the management listener until one is selected and validated.
- The selected verifier is PBKDF2-HMAC-SHA256 with 600,000 iterations and a
  random 32-byte salt, compared with `hmac.compare_digest`. Accept 8-32
  character passwords containing lowercase, uppercase, and numeric characters,
  reject documented default strings, and require matching confirmation.
  Setup/login share a global five-attempts-per-minute limit;
  allow at most eight live sessions. Measure hashing latency on the board
  before release; do not silently reduce the work factor.
- After successful setup, disable setup requests until console/SSH recovery
  explicitly reprovisions the device. Require the session for every management
  page and CGI endpoint, retaining only the public login shell and handler.
  There is no browser password reset
  or account recovery in this release; reset/reprovision through the trusted
  console/SSH procedure, removing the verifier and generating a new one-time
  setup token. Keep the setup wizard and token limited to the UI account; they
  do not change device login or VPN identities.
- Password-only form login and session cookies do not encrypt HTTP traffic.
  A web-admin password prevents casual
  unauthenticated access but does not protect credentials or VPN secrets from
  an observer on the LAN. Use a unique strong password, and explain this
  limitation on the login/setup instructions.
- Run BusyBox `httpd` and CGI as root because the existing management scripts
  require root; remove the current `-u www-data` drop when deploying the
  authenticated management UI, not as a standalone change to the unauthenticated
  placeholder service. A CGI vulnerability can compromise the entire device;
  this larger impact is accepted in favor of the simpler implementation.
  The web-admin identity therefore has the effective authority to manage
  the VPN, even if it is separate from the root SSH account. This is not a
  restricted or multi-user authorization system.
- No Node.js, Docker, database, or persistent web application process is needed.
  Use plain HTML, CSS, and vanilla JavaScript. The design may take general
  usability and visual inspiration from
  [wg-easy](https://github.com/WeeJeWel/wg-easy/tree/master/src/www). Review
  its typography, colors, spacing, page composition, cards, tables, icons, and
  available imagery. Reuse font files, images, icons, or other assets only
  after verifying that their specific licenses permit redistribution and that
  required notices/attribution are included. Do not copy source code or
  branding by default; where assets cannot be reused, create original
  equivalents with a similar visual feel. Keep all assets local in the firmware
  so the UI has no runtime dependency on external hosts.

## 5. CGI/API contract

Use same-origin `fetch()` requests and JSON for API responses. For mutations,
use `POST` with `application/x-www-form-urlencoded` bodies. Parse forms with the
Python standard library, rejecting unknown/duplicate fields and malformed
encoding; use its JSON encoder for responses. Query strings
are only for read/download operations. Every endpoint must:

- Accept only its documented HTTP method and fields; impose a small request-body
  size limit and reject malformed or duplicate fields.
- Decode URL encoding exactly once, then validate client names against the
  existing CLI rule. Pass values as quoted positional arguments, never through
  `eval`, a constructed shell command, or unquoted expansion.
- Return valid JSON with `Content-Type: application/json` and `Cache-Control:
  no-store` for API data. A successful response has `{"ok":true,...}`; a failure
  has `{"ok":false,"error":{"code":"...","message":"..."}}` and a suitable
  HTTP status. Escape every dynamic JSON string correctly.
- Return a non-zero/HTTP error when a command fails. Do not turn a failed
  `wg show`, missing config, lock contention, or restore failure into an empty
  success response. Do not include private keys, preshared keys, full client
  profiles, or backup contents in JSON, logs, or error messages.
- Use a shared lock on `/run/pivpn.lock` while taking a read snapshot so the
  client metadata and WireGuard status do not race the CLI's atomic file
  updates. Mutations must rely on the lock taken by the existing `pivpn`
  command; do not hold the lock in the CGI and then call `pivpn`, which would
  self-conflict. Report a busy lock as a retryable error.
- System-only metric reads do not need the VPN lock. Serialize LED changes
  through a separate LED lock shared with startup; do not use the VPN lock or
  invoke the network init script for LED actions.
- Validate `HTTP_ORIGIN`/same-origin request metadata for mutations and require
  a same-origin custom request header. Do not enable permissive CORS. This
  prevents unrelated web pages from using the LAN listener to
  trigger state changes.

### Endpoint definitions

| Endpoint | Method and input | Behavior and response |
|---|---|---|
| `/cgi-bin/vpn.cgi/state` | `GET`, public | Returns only whether token-gated setup is required, never a token or system metrics. |
| `/cgi-bin/vpn.cgi/app` | `GET`, session required | Returns private management HTML with `no-store` and restrictive security headers. |
| `/cgi-bin/vpn.cgi/setup` | `POST token,password,password_confirm` | Before provisioning only: validate token/password, atomically persist the verifier, consume the token, and require login. Rate-limit and require same-origin checks. |
| `/cgi-bin/vpn.cgi/login` | `POST password` | Verify password, rate-limit, and issue a short-lived session cookie. Same-origin checks required; no credential logging. |
| `/cgi-bin/vpn.cgi/logout` | `POST`, empty body | Same-origin checks/custom header required. Revoke only the current session and expire its cookie. Missing/expired sessions succeed; storage errors do not. The old cookie must stop working. |
| `/cgi-bin/vpn.cgi/status` | `GET` | Interface running state/name/live IPv4/listen port; configured endpoint/DNS/MTU/AllowedIPs; uptime, raw CPU/network counters, load, RAM/swap, storage, temperatures and aggregate LED state. Browser computes rates from consecutive samples. No private keys. A stopped interface is valid; unavailable readings are explicit. |
| `/cgi-bin/vpn.cgi/leds` | `POST enabled=1\|0` | Fixed global helper for all three LEDs, with no arbitrary LED/path/trigger input. Enable `eth_link` netdev link, `eth_act` netdev RX/TX, and `work` activity; disable using `none` plus brightness zero. Report partial failures and resulting aggregate state. Runtime-only; never manipulate networking. |
| `/cgi-bin/vpn.cgi/clients` | `GET` | All configured clients, including disabled ones: name/IP/creation/enabled state and live handshake/endpoint/RX/TX when available. No client private/preshared keys. Keep configured clients visible when wg0 is down. |
| `/cgi-bin/vpn.cgi/client-add` | `POST name` | Validate and invoke `pivpn add -n "$name"`; report success only on command success and distinguish saved-but-not-live when wg0 is down. |
| `/cgi-bin/vpn.cgi/client-enable` | `POST name` | Invoke `pivpn on "$name" -y`, retaining existing CLI idempotence. |
| `/cgi-bin/vpn.cgi/client-disable` | `POST name` | Confirm in UI, then invoke `pivpn off "$name" -y`; traffic revoked, profile retained. |
| `/cgi-bin/vpn.cgi/client-remove` | `POST name` | Confirm irreversible deletion of profile/keys, then invoke `pivpn remove "$name" -y`. |
| `/cgi-bin/vpn.cgi/client-config?name=...` | `GET` | Exact validated existing profile as `text/plain` attachment, `no-store`; never log contents. |
| `/cgi-bin/vpn.cgi/client-qr?name=...` | `GET` | On-demand SVG from `qrencode -t SVG -o - -r <fixed-profile-path>`, `no-store`. Verify SVG support on target; do not return ANSI QR output. |
| `/cgi-bin/vpn.cgi/backup-create` | `POST`, empty body | Invoke backward-compatible `pivpn backup --web` machine-output mode; return only basename/timestamp. Use collision-safe numeric suffixes, checked tar/gzip pipeline, atomic publication and newest-five retention with numeric tie ordering. |
| `/cgi-bin/vpn.cgi/backups` | `GET` | List regular non-symlink `pivpnbackup-YYYYmmdd-HHMMSS[-N].tgz` files in the fixed directory, returning basename/size/mtime. |
| `/cgi-bin/vpn.cgi/backup-download?file=...` | `GET` | Open validated basename under read lock and stream the descriptor as attachment, `no-store`, without copying the archive into RAM. Warn that it contains secrets. |
| `/cgi-bin/vpn.cgi/backup-upload` | `POST`, raw `application/gzip`, `X-VPN-Backup-Name` header | Require Content-Length <=16 MiB and sufficient disk space; require an original `pivpnbackup-YYYYMMDD-HHMMSS[-N].tgz` basename, stream to private temporary storage in <=64 KiB chunks, require complete body, validate with the CLI's shared archive validator, then atomically publish under the uploaded name. A same-named backup is replaced only after validation; failures preserve it. Modified time reflects upload, not the timestamp in the filename. Clean up failures. |
| `/cgi-bin/vpn.cgi/restore` | `POST file` | Confirm disruption; validate a listed regular backup and invoke `pivpn restore "$path" -y`. CLI validates and extracts with the shared bounded validator before replacing state/restarting wg0; report failures and refresh after success. |

The shared validator rejects links, devices, duplicate/traversal paths,
unexpected files, executable shell settings/WireGuard hooks, corrupt gzip,
incomplete backups, more than 1,024 entries, individual files over 1 MiB, and
expanded input over 32 MiB. This intentionally supports backups of this fixed
`eth0`/`wg0`, /24 appliance, not arbitrary PiVPN installations. Previously
hand-edited archives with additional files/hooks/settings may be rejected.

For live client status, derive the UI's `recent handshake` indicator from the
WireGuard latest-handshake timestamp: call it recent only when it is non-zero
and no more than 180 seconds old. This is a display heuristic, not proof that a
client is currently reachable. The board has no battery-backed RTC; label
timestamps as approximate until NTP has synchronized. Show RX/TX as bytes since
the current WireGuard interface was started, not lifetime usage.

## 6. Web pages and behavior

### Visual direction

- Light mode is the default for login/setup and management pages. A Settings
  "Dark mode" switch in Settings and at the upper-right of login/setup saves
  only `light`/`dark` in browser localStorage. Restore it before rendering on
  both pages, including after logout/session expiry and browser restarts.
  Default to light for missing/invalid preferences; synchronize open tabs.
  Preferences are browser-profile/origin-specific, not device settings or
  credentials. Report storage failures while allowing temporary theme changes.
  Keep readable contrast and theme-appropriate chart colors.
- Include the user-supplied WireGuard logo locally. The user confirmed
  permission to redistribute and recolor it. Render the original red silhouette
  for light mode and dashboard light green (`#53dfb3`) for dark mode using the
  same transparent PNG as a CSS mask; do not fetch external assets.
- Recreate the reference UI's overall visual language: typography, color
  palette, spacing, surface/card treatment, client-list layout, icon style, and
  use of imagery. Keep the information hierarchy and interactions suitable for
  a small VPN appliance rather than reproducing unrelated wg-easy features.
- Before implementation, record the exact font and asset files proposed for
  reuse and verify their individual licenses and attribution requirements.
  Bundle approved files locally. For any asset without clear redistribution
  permission, use an original or appropriately licensed substitute with a
  similar look; do not hotlink assets from GitHub or another remote host.
- Preserve readability and status meaning: accessible contrast, clear
  enabled/disabled/error states, responsive layout for phone and desktop, and
  no reliance on color alone to convey state.

### Dashboard

- Show whether `wg0` is running, its tunnel address and UDP listen port, plus a
  clear error/empty state if it is unavailable.
- Show configured public endpoint and recent client count. Clarify that "recent"
  uses the 180-second handshake heuristic.
- Show per-client RX/TX only as current-interface counters. Do not present
  counters as historical usage or billing data.
- Refresh status at a modest interval (for example, every 10 seconds) only while
  the page is visible. Stop polling while hidden; do not poll QR/profile data.

### Clients

- Use a compact client list inspired by the supplied layout: avatar/recent-
  handshake indicator, name/IP, sampled RX/TX rates, an enable/disable switch,
  and labeled QR/download/delete icon buttons. Provide a "+ New" header action
  with a name-entry dialog. Keep creation time, absolute handshake, endpoint
  and total counters available in expandable details; do not lose existing
  client data to achieve the compact layout.
- Use keyboard-accessible switches with explicit labels and checked state.
  Retain confirmation before disabling a client; switches reflect server
  results, not optimistic success. Compute rates only after two valid samples,
  and label unavailable/reset counters rather than fabricating rates.
- List enabled and disabled clients with name, virtual IP, creation time, status,
  last handshake, remote endpoint, and current RX/TX where available.
- Provide create, enable, disable, remove, profile-download, and show-QR
  actions. Require a name for creation; never generate an implicit name or
  silently overwrite an existing client.
- Confirm disable/remove actions before making the request. Removal is
  irreversible from the UI and should state that the client's stored profile
  and key material will be deleted. Require a separate confirmation for restore.
- Display profile/QR only on explicit user action. Hide it when the dialog is
  closed, do not store it in local storage, and do not add it to browser logs,
  analytics, or URL parameters. Warn that anyone who scans or downloads it can
  use that client identity.
- Refresh the list from the server after each mutation. Do not optimistically
  show success before receiving a successful API response.

### Settings and system information

- Show active values such as endpoint, port, tunnel subnet, DNS, MTU, and
  AllowedIPs, plus a concise system-health overview with CPU usage/load,
  memory/swap, relevant filesystem capacity, temperatures, and network
  throughput when those measurements are available on the target. Label each
  metric and its units; show unavailable data as unavailable rather than
  inferring or fabricating a value. Keep sampling and polling lightweight for
  the 64 MB board.
- Limit the overview to summary metrics and short live charts, including
  `eth0`/`wg0` traffic rates and uptime; no process table or process-management
  actions. Read kernel/system counters directly, never launch or scrape btop.
  Compute rates from consecutive samples without sleeping in CGI, handle
  counter resets and missing interfaces, and keep bounded chart history only
  in browser memory; no persistent metrics daemon or history database.
- Provide one global "System LEDs" enable/disable control that acts on
  `eth_link`, `eth_act`, and the onboard `work` LED together, using only the
  fixed trigger/brightness behavior in the LED API contract. Do not provide
  per-LED controls. Display aggregate state and operation errors; show a mixed
  or unavailable state explicitly rather than a misleading enabled/disabled
  toggle. Enabled means the configured triggers are active, not that every
  LED is currently illuminated.
- Render the global LED operation as one labeled switch. Distinguish mixed
  state with explicit text and a centered/dashed switch treatment; switching
  from mixed enables all. Disable the switch for unavailable controls rather
  than displaying them as a valid off state.
- Extract a fixed LED-only helper shared by startup and the GUI. It must not
  change the MAC address, cycle `eth0`, or run `S39lan start/stop`; preserve
  the existing startup order and missing-interface behavior.
- LED choices are volatile and are not written to configuration or persisted.
  The system startup script may re-enable the configured LED triggers after a
  reboot; explain this behavior in the UI.
- This global LED control is the only system-setting mutation in the first
  release. Do not offer editing of `setupVars.conf`, `wg0.conf`, the firewall,
  SSH, or other system settings; there is no existing validated apply/rollback
  flow for them.
- Mark unavailable values as unavailable; do not infer a setting from a
  hard-coded UI default.

### Backup

- Show create, list, and download actions for the existing five-retained backup
  set. Clearly explain that backups are unencrypted and contain VPN private
  keys; downloading one transfers those secrets to the administrator's PC.
- Upload off-device backups through the UI using the bounded raw-body endpoint;
  do not implement multipart parsing or buffer archive data in RAM. The 16 MiB
  limit must be checked against available `/userdata` space before accepting
  the body. Reject oversized, truncated, malformed, or unexpected-path archives
  and remove incomplete temporary files.
- Restore is deliberately disruptive: it stops and restarts `wg0`, replaces
  current keys/clients/settings, and retains the previous WireGuard directory
  as `.prev`. The previous directory is not a full rollback of `/etc/pivpn`;
  keep an off-device copy regardless.

## 7. Security and reliability requirements

- No general-purpose command endpoint, shell terminal, arbitrary file path, or
  arbitrary config editor. The sole setup exception is the one-time,
  token-gated UI-account wizard, available only before account creation.
- Serve direct HTTP only on the trusted home LAN, with web-admin authentication.
  This is deliberately unencrypted: credentials and VPN secrets returned by
  profile/QR/backup endpoints can be observed by someone able to monitor the
  LAN. Do not use on untrusted networks and do not add a router port forward.
- Bind only to the LAN IPv4 address where supported, or enforce equivalent
  restrictions with the firewall; do not expose on WAN, USB-RNDIS, or IPv6.
  Verify from another LAN host and from USB/WAN-reachable paths rather than
  assuming the bind/firewall configuration is effective.
- Require a valid web-admin session for management pages and every management
  CGI endpoint. Only login/setup shells and their restricted handlers are
  public. Do not put protected management HTML in directly served static files;
  gate it through authenticated CGI. Protect `/userdata/webui/auth.conf` and
  `/userdata/webui/setup-token` under a root-owned mode-`0700` directory; the
  files must be mode `0600`. The pre-account wizard must require the device's
  one-time setup token; no default credential, persisted plaintext password,
  or home-grown cryptography.
- Restrict the pre-account state to the static wizard shell/assets, nonsensitive
  setup-required indicator, and setup endpoint. The one-time token must be checked on the device, compared
  safely, rate-limited, and atomically consumed after successful account
  creation. Verify concurrent requests cannot create or replace a second
  account.
- Keep all client secrets and backups on `/userdata` with the permissions
  already required by the VPN implementation. Static UI and CGI code must
  contain no credentials.
- For mutation and download handlers, validate all parameters, use fixed
  executable paths and quoted arguments, and constrain file selection to the
  expected directory and basename. Do not trust a client-supplied path.
- The LED endpoint is limited to the fixed supported LED set and trigger
  actions, with no per-LED selection. It must not expose arbitrary sysfs
  access. Report partial-write failures and the resulting aggregate state,
  and do not persist an enable/disable preference.
- For backup uploads, enforce the 16 MiB body cap before reading, stream to
  private temporary storage, validate the complete archive before making it
  visible in the backup list, and clean up on every failure path.
- Use the existing `pivpn` lock and semantics for VPN state changes, the
  separate LED lock for LED changes, and independent serialization for
  setup/session state. Handle
  concurrent requests, failures, and a stopped interface visibly. Never report
  success solely because a CGI process started.
- Apply `Cache-Control: no-store` to all API, profile, QR, and backup responses.
  Do not log request bodies, profiles, QR payloads, keys, or archive contents.
- Require same-origin mutation requests, validate `Origin` where supplied, and
  reject cross-origin mutation requests. This is defense in depth, not
  transport security; it does not prevent an on-path LAN observer from
  capturing HTTP credentials or response data.
- Restrict response headers and content types. Escape text inserted into the
  page; render client names and messages as text, not HTML. Do not use third-
  party scripts, analytics, or remote fonts at runtime. Serve any legally
  reusable fonts/images/icons from local firmware files.
- Keep the UI responsive but small for the device and its clients. Avoid large
  frontend frameworks, build-time runtimes on the board, and unnecessary
  background polling.

## 8. Implementation and verification sequence

1. Confirm BusyBox `httpd` CGI, LAN bind, request-cookie access, and response-header
   support; the available `qrencode` output format; web-root conventions; and
   an unused init sequence in the actual Buildroot image. Verify the chosen
   password hashing/authentication integration, one-time token generation and
   protected retrieval procedure, and review licenses for proposed reference
   fonts and assets. Also implement and test collision-safe backup naming in
   the existing CLI before exposing backup creation through the UI.
2. Extend the existing `/var/www` assets and `S49httpd` service in the VPN
   overlay; do not create a competing web root or listener. Initialize private
   persistent auth storage and volatile session storage, and switch to root
   execution only with the authentication gates in place. Verify the service
   starts after DHCP and WireGuard, retries late/missing DHCP, and stops
   cleanly including pending retries. Confirm
   that the listener cannot be reached through USB-RNDIS, IPv6, or a WAN path.
3. Implement read-only CGI responses and the shared safe JSON/form parsing
   helpers, including low-cost system metrics and current LED state. Verify
   JSON escaping, missing/down-interface behavior, unavailable metrics,
   invalid methods, malformed inputs, and bounded request sizes.
4. Implement and test the password-only token-gated first-boot wizard,
   credential verifier storage, custom login/logout, short-lived session cookies,
   atomic one-time setup, and console/SSH recovery. Test session expiry even
   with active polling, reboot invalidation, bounded session storage, cookie
   attributes, rate limiting, and protection of directly requested management
   pages as well as APIs. Test logout invalidates the old cookie, leaves other
   sessions intact, succeeds for absent/expired sessions, rejects cross-origin
   requests, and reports storage failures. Verify pending responses and browser
   Back navigation cannot restore sensitive content or authenticated access
   after logout.
   Confirm all management endpoints remain inaccessible before setup and the
   wizard is disabled afterward.
5. Implement mutating CGI adapters that invoke only the corresponding `pivpn`
   commands, plus the shared LED-only helper and global LED enable/disable
   operation. Test that LED actions never alter networking and that one
   control changes all three LEDs, aggregate state reporting,
   unsupported/missing LED handling, partial sysfs write failures,
   and that reboot startup may re-enable LEDs without a saved preference. Test
   create, disable, enable, remove, duplicate-name rejection, invalid names,
   lock contention, and command failure. Keep existing client command behavior
   unchanged. CLI changes are limited to collision-safe backup naming/retention,
   optional machine-readable backup output, and the shared safe archive
   validator/extractor used by both upload and restore.
6. Implement profile/QR and backup endpoints, including bounded raw-body
   uploads. Verify downloads match the existing files byte-for-byte, all
   secret-bearing responses are marked no-store, and no secrets appear in logs
   or errors.
7. Exercise backup creation, listing, download, upload, and restore on a test
   board or isolated test state before relying on it for recovery. Test the
   size limit, truncated uploads, invalid archives, disk-full behavior,
   collision-safe naming, the effect on active peers, and `.prev` behavior.
8. Test direct access from an authenticated home-LAN browser at
   `http://192.168.0.10:8080`. Confirm unauthenticated requests fail,
   token-gated first setup works only once, cross-origin mutations are rejected,
   and access is unavailable through USB-RNDIS, IPv6, and WAN. Document that
   HTTP traffic is visible to LAN observers; do not treat this verification as
   encryption.
9. Test after reboot and with `wg0` stopped. Check memory footprint, CGI
   response time, system metric availability, LED control behavior, and that
   status polling is modest on the 64 MB board.

## 9. Acceptance criteria

- The web UI is served from the target image without Node.js, Docker, a database,
  or a persistent application runtime.
- The UI is directly reachable over HTTP from an authenticated browser on the
  trusted home LAN and is not reachable through WAN, USB-RNDIS, or IPv6.
- A web-admin credential is required for all management pages and APIs. Before
  account creation, only a one-time-token-gated setup wizard is available; no
  default credential or open setup path exists.
- Login uses a password-only custom form and a short-lived session cookie,
  with no username. Explicit logout invalidates the current server-side
  session, clears its cookie and sensitive browser state, and returns to login.
  Idempotent logout, old-cookie rejection, session expiry, reboot invalidation,
  and rejected unauthenticated direct requests are verified.
- The plan and setup instructions clearly state that HTTP does not encrypt
  credentials, client profiles, QR payloads, or backups on the LAN.
- UI client actions match `pivpn` behavior, persist across reboot, and show
  command/validation errors rather than success-shaped fallbacks.
- Disabled clients remain visible and distinguishable from deleted clients.
- A stopped `wg0` does not prevent reading configured clients and is clearly
  distinguished from an empty client list.
- The system overview displays available critical resource metrics with
  units and explicit unavailable states, and provides one global control to
  enable/disable all Ethernet and onboard work LEDs together, with no per-LED
  controls. LED changes are runtime-only; startup may re-enable the triggers
  after reboot.
- Summary metrics and short live charts do not include a process table or
  persistent history. LED actions do not change network configuration.
- Profiles, QR codes, and backups are delivered only on explicit request and
  are never cached, logged, or placed in the static web root.
- Backup restore works only for a validated staged archive, warns about the
  interruption, and reports success only after the restore command completes.
- Backup upload works over HTTP within a strict size limit without buffering
  the archive in RAM; invalid or incomplete uploads never become restorable
  backups.
- Reused reference fonts/assets have verified licenses and required notices;
  all browser assets are served locally.
- The first-boot wizard creates only the UI account and cannot alter Linux,
  SSH, or WireGuard identities. No configuration-editing feature is presented
  as implemented in this release.
