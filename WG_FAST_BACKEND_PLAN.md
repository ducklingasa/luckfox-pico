# LuckFox Pico Mini A: WireGuard Web UI Optimization Plan

## 1. Goal, environment, and status

Reduce dashboard refresh latency and CPU/memory pressure without weakening
authentication, changing the API, or disrupting VPN traffic. The native
implementation and permanent native firmware wiring are now delivered; validation and
remaining qualification are recorded in [WG_GUI_IMPL.md](./WG_GUI_IMPL.md).
The native board results are recorded in the result-summary section. Following
those results, the user approved permanent native dashboard routing and removal
of the legacy selector/CGI and duplicate Python hot-read handlers. Python
remains required for initialization, authentication and cold management routes.
The initial legacy baseline below is retained unchanged; rollout/rollback
proposals from the initial plan have been superseded as described below.
The cleanup passed 72 regression tests, 25 native sanitizer tests and final
firmware-image checks; details are in the implementation document.

- RV1103, single-core ARM Cortex-A7, 64 MB RAM; measure actual CPU frequency
  and available memory on the flashed image.
- Buildroot Linux, BusyBox `httpd`, WireGuard `wg0`, short-lived Python CGI.
- Persistent state: `/userdata/webui`, `/userdata/wireguard`,
  `/userdata/vpn-backup`, `/etc/pivpn/wireguard/setupVars.conf`.
- Volatile state: `/run/webui` and `/run/pivpn.lock`.
- Preserve the trusted-LAN-only HTTP deployment, binding/firewall restrictions,
  and absence of a persistent application server. HTTP remains unencrypted.
- Actual deployment: one configured client, fewer than 10 expected. Optimize
  for one dashboard tab and this small client count, not a large peer fleet.

Current behavior and acceptance requirements remain documented in
[WG_GUI_IMPL.md](./WG_GUI_IMPL.md) and [WG_GUI_PLAN.md](./WG_GUI_PLAN.md).

## 2. Baseline bottlenecks and corrected assumptions

| Area | Current behavior | Implication |
|---|---|---|
| CGI startup | The original shell CGI started `/usr/bin/python3 -I -B /opt/vpn-web/webui.py` for every accepted request; that legacy CGI has now been removed. | Interpreter startup/imports were candidates for optimization; the original 150-400 ms estimate needed board measurements. |
| Request gate | The shell holds an exclusive `/run/webui/request.lock`, tries five nonblocking acquisitions, and sleeps 0.1 seconds after each failure before returning HTTP 503 `busy`. | Contention can add roughly 0.5 seconds, but removing serialization for all Python requests could multiply memory use. |
| Browser polling | [app.js](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/var/www/app.js) already awaits `status`, then page-specific `clients` or `backups`; polling runs every 10 seconds, skips hidden/busy pages, and queues navigation. | A single tab does not issue parallel status/client polls. Multiple tabs/users, external CLI work, or interpreter teardown can still cause contention. |
| Subprocesses | A running interface costs two commands in `status` (`wg`, `ip`) and three `wg show` commands in `clients`. | A dashboard refresh executes five utility subprocesses in addition to two Python startups. |
| VPN locking | [webui.py](./project/cfg/BoardConfig_IPC/overlay/overlay-luckfox-vpn/opt/vpn-web/webui.py) already takes shared, nonblocking `/run/pivpn.lock` locks for reads; CLI mutations take exclusive locks. | Native reads must retain this coordination. Shared locks permit concurrent readers, not readers during a mutation; existing conflicts return HTTP 409 `busy`. |
| Authentication | PBKDF2-HMAC-SHA256 uses 600,000 iterations under `auth.lock`, inside the outer request gate. | Benchmark setup/login separately. Native CGI cannot eliminate their single-core CPU cost, and authentication can still contend with polls. |

Do not treat 1-3 ms latency, zero total idle RAM, or <0.5 MB peak request RAM
as established results. CGI avoids an additional resident application daemon;
`httpd`, its connection workers, libraries, and overlapping requests still use RAM.

## 3. Initial live-board baseline and simple repeat test

### 3.1 Original backend result (2026-10-29)

One configured client; browser instrumentation observed the dashboard's existing
sequential `status`/`clients` requests without generating extra polls. Each run
lasted 310 seconds. These are user-collected results, not a direct assistant
connection or server-side profile.

| Measure | Idle | VPN active |
|---|---|---|
| Successful samples per endpoint / complete refresh | 28 / 28 | 30 / 30 |
| `status` p50 / p95 / max | 954 / 979 / 982 ms | 1428 / 3378 / 3518 ms |
| `clients` p50 / p95 / max | 966 / 980 / 981 ms | 1380 / 3018 / 3393 ms |
| Complete refresh p50 / p95 / max | 1916 / 1935 / 1947 ms | 2986 / 6186 / 6269 ms |
| Observed request failures | 0 | 0 |
| Whole-system average CPU | 18.0% | 53.2% |
| Minimum sampled MemAvailable | 34.3 MiB | 34.3 MiB |
| Tab hidden at some point | Yes | No |
| Counter observation interval | 299.99 s | 287.61 s |
| `wg0` RX / TX counter increase | 0 / 0 bytes | 229,532,016 / 227,747,120 bytes |

During the active interval, interface counters averaged approximately
6.38 Mbit/s RX and 6.33 Mbit/s TX. These are interface byte rates, not a
speed-test result or the VPN's maximum throughput. Forwarded traffic can
contribute to both directions; do not sum them as unique client goodput.

Interpretation and limits:

- The measured problem is responsiveness: about 1.9 seconds per idle refresh,
  rising to a 6.2-second p95 during VPN use. Active median refresh time was
  1.56x idle and p95 was 3.20x idle. Small sample counts make p95 indicative,
  not a precise tail-latency guarantee.
- Both endpoints are slow even with one client. Large-client scaling is not
  the initial problem; repeated per-request work is a stronger investigation
  priority than optimizing traversal of a large peer list.
- No busy/error responses were observed. Lock contention remains a correctness
  concern, not a demonstrated cause of these timings. Do not equate elapsed
  time with gate waiting or Python startup.
- CPU increased under VPN load, but these are whole-system averages including
  the UI, VPN and other tasks. Neither 18% nor the 35.2-percentage-point increase
  can be attributed solely to polling or VPN encryption from these runs.
- Sampled memory shows useful headroom, not demonstrated memory pressure.
  It does not measure transient CGI peaks or prove the absence of OOM events.
- Browser durations include LAN/browser scheduling, response-body processing
  and instrumentation overhead. They do not isolate server execution, imports,
  subprocesses or HTTP transport. Firmware revision, clock/thermal state,
  cold-cache behavior and login time were not captured.
- The idle tab was hidden at some point, suppressing some polls and potentially
  changing browser scheduling. Keep these results as a provisional baseline;
  do not use them to claim a controlled idle/active CPU comparison.

### 3.2 Small before/after protocol

No 100-sample, 32/253-client, or four-session board matrix is needed initially.
Use the existing one-client board:

1. Record the firmware revision and keep the same browser, LAN connection,
   one dashboard tab, and 10-second polling interval.
2. Observe approximately 30 refreshes over five minutes while idle. Keep the
   tab visible throughout; rerun the idle baseline this way for final comparison.
3. Repeat with the same client carrying a repeatable VPN workload, preferably
   the same sustained download. Keep it running throughout the measured period
   and record its reported speed, without treating that as a capacity benchmark.
4. Report endpoint and complete-refresh p50/p95/max, errors, whole-system CPU,
   sampled available memory, and interface byte rates, as above.
5. After optimization, repeat both runs under comparable conditions and smoke
   test normal management actions. Use synthetic fixtures for 0-9 clients;
   there is no need to create dummy clients on the live board.

Do not run restore, remove the real client, or change credentials merely to
collect a performance baseline. Server-side stage timings or a polling-off
comparison are follow-up diagnostics only if needed to identify the remaining
bottleneck or quantify polling's CPU/throughput cost.

### 3.3 Native backend result summary (2026-11-01)

User-collected live-board measurements ran for 310 seconds each, with the tab
visible throughout. Each run recorded 31 successful samples per endpoint and
31 complete refreshes. No request failures or instrumentation notes were
reported: 124 sampled endpoint requests succeeded across both runs.

| Measure | Native idle | Native VPN active |
|---|---|---|
| `status` p50 / p95 / max | 53 / 63 / 65 ms | 58 / 80 / 85 ms |
| `clients` p50 / p95 / max | 36 / 45 / 53 ms | 45 / 65 / 66 ms |
| Complete refresh p50 / p95 / max | 86 / 105 / 109 ms | 105 / 141 / 142 ms |
| Whole-system average CPU | 1.2% | 34.3% |
| Minimum sampled MemAvailable | 38.5 MiB | 38.5 MiB |
| Counter observation interval | 300 s | 299.99 s |
| `wg0` RX / TX counter increase | 0 / 0 bytes | 315,002,276 / 290,362,976 bytes |
| Observed request failures | 0 | 0 |

Compared with the provisional legacy baseline in section 3.1:

- Median complete refresh decreased from 1,916 to 86 ms idle (about 22x
  faster), and from 2,986 to 105 ms under VPN load (about 28x faster).
- Complete-refresh p95 decreased from 1,935 to 105 ms idle (about 18x
  faster), and from 6,186 to 141 ms under VPN load (about 44x faster).
- Whole-system average CPU was lower by 16.8 percentage points idle and
  18.9 percentage points under VPN load. These are not per-request CPU costs.
- Minimum sampled available memory increased by 4.2 MiB in both runs.
- Active interface counters averaged approximately 8.40 Mbit/s RX and
  7.74 Mbit/s TX, versus approximately 6.38/6.33 Mbit/s previously. These
  are interface byte rates, not maximum VPN throughput or unique client
  goodput; do not sum both directions as unique transferred traffic.

**Assessment:** the observed native runs comfortably meet the provisional
complete-refresh p95 targets (600 ms idle, 2,000 ms active), the zero-error
goal and the minimum sampled memory target (30 MiB). The worst observed
refresh was 142 ms during VPN activity. These results support retaining the
native hot-read architecture; no further dashboard optimization is justified
by the measured responsiveness.

**Qualification limits:** the earlier idle baseline included a hidden tab,
and identical active workloads were not established. The speedups are strong
indications, not controlled guarantees. With 31 refreshes per run, p95 remains
indicative rather than a tail-latency guarantee. Sampled memory does not capture
transient process peaks, and the interface rates do not establish a throughput
ceiling or a formal non-regression bound. Management, authentication,
compatibility smoke tests remain separate acceptance gates;
repeat a matched visible-tab legacy baseline for formal before/after claims.

## 4. Recommended architecture: native hot reads, serialized Python cold paths

Keep `/cgi-bin/vpn.cgi/<operation>` and its existing request/response contract.
Use a small native front controller at the existing CGI location; do not add a
second public API or change browser URLs. Prioritize `status` and `clients`:
the baseline supports reducing their repeated work, but does not yet prove
which part of the current request dominates or how much native code will save.

| Route | Implementation | Access |
|---|---|---|
| `GET /state` | Existing Python initially | Public; only the existing `{ok, setup}` information. Native handling is optional later, not needed to improve dashboard polling. |
| `GET /status`, `GET /clients` | Native | Existing session required; no secrets in responses. |
| `GET /app`, `/backups`, `/client-config`, `/client-qr`, `/backup-download` | Existing Python | Preserve private HTML, streaming/download behavior, and authorization. |
| All existing POST operations | Existing Python | Preserve origin checks, validation, limits, CLI integration, and error handling. |
| Unknown routes or unsupported methods | Existing error contract | No new fallback that turns an invalid request into a successful read. |

The native fast path must not launch Python, `wg`, `ip`, a shell, or another
helper. Cold requests acquire the existing bounded exclusive request gate and
then `execv()` Python with `-I -B`; do not allow multiple heavyweight Python
requests merely because the native gate was removed. Use fixed executable paths
and preserve CGI environment, stdin, stdout, stderr, and exit behavior.

Native routing is now permanent, using a public CGI symlink directly to the
native ELF. The initial deploy-time selector and legacy shell rollback option
have been removed following user approval. Python no longer duplicates
`status`, `clients`, settings parsing or dashboard metrics collection; it still
handles initialization and all used cold routes. Unsupported methods on native
dashboard routes retain HTTP 405 without invoking Python. Failed native reads
are never retried through Python: expose failures and fix them.

### 4.1 Session compatibility and lock design

Native session validation is an authentication implementation, not just a file
existence check. Specify and test the shared Python/C storage contract first:

- Accept exactly one `vpn_session` cookie with exactly 64 lowercase hex
  characters; reject duplicates, traversal, malformed values, and truncation.
- Require the configured web-admin account as Python does; `/state` remains
  public and must not require a session.
- Check root-owned private directories/files and use safe descriptor-relative
  opens with no symlink following. Never derive an arbitrary filesystem path
  from a cookie. Missing/expired sessions return 401; corrupt or inaccessible
  storage returns an explicit internal error, not authenticated success.
- Session contents are the ASCII floating-point issue time from `/proc/uptime`,
  not filesystem mtime or wall-clock time. Parse the entire value, reject
  nonfinite/invalid values, and require `issued <= now < issued + 1800`
  (equivalent to `0 <= now - issued < 1800`, without subtractive rounding at
  the exact fractional expiry boundary).
  Read `/proc/uptime` with compatible precision; integer `sysinfo().uptime`
  can incorrectly reject a newly issued fractional-time session.
- Polling must not renew sessions. Preserve reboot invalidation, logout
  revocation, the eight-session cap, and provisioning invalidation.
- Use a short shared, nonblocking `auth.lock` while validating; Python retains
  exclusive ownership for login/setup/logout and session cleanup. Move expired
  session deletion out of native reads; retain cleanup on Python auth operations
  and initialization. Test the changed cleanup timing explicitly.
- Release `auth.lock` before acquiring `/run/pivpn.lock`; never hold both across
  a slow collection or response write. Document lock order for every path.
  An already authorized in-flight request may finish after logout, as today;
  subsequent requests must fail and the browser must discard aborted results.
- Shared auth/VPN locks can still conflict with exclusive writers. Preserve
  explicit HTTP 409 `busy` for these conflicts; do not spin, block indefinitely,
  return stale data as fresh, or promise that all busy responses disappear.
- Keep shared VPN locks only while copying configuration and live state into
  bounded request-local storage. Release before serialization/network output.
  CLI writers are nonblocking, so test writer failures/starvation under readers.

The native controller's cold-request gate can still delay logout behind another Python operation.
Preserve the visible unconfirmed-logout/retry behavior; do not claim revocation
when the server has not confirmed it.

### 4.2 Zero-helper WireGuard and interface collection

Implement the missing native data path explicitly:

- Use Linux Generic Netlink (`wireguard` family, `WG_CMD_GET_DEVICE`) for the
  live listen port and peer public keys, latest handshake times, RX/TX byte
  counters, and endpoints. Use route netlink (`RTM_GETADDR`) for the live `wg0`
  IPv4 address/prefix; configuration alone is not the live interface state.
- Prefer a small established netlink helper such as `libmnl`, declared through
  Buildroot if needed. Regardless of library, validate attribute sizes/types,
  nested attributes, message sequence/sender, multipart completion, interrupted
  dumps, `NLMSG_ERROR`, truncation, and timeouts. Bound retries and total work.
- Merge peer fragments by public key: large WireGuard dumps may span messages.
  Do not assume one receive or one message contains the whole device.
- Netlink device responses can contain private/preshared keys. Extract only
  allowlisted fields, never serialize/log raw buffers, and clear sensitive
  buffers before release. Do not use `wg show ... dump` as a shortcut.
- Join live public keys to `configs/clients.txt` and enabled/disabled markers
  in `wg0.conf`; preserve configured peers when the interface is down.
  Preserve `null` versus zero, endpoint formatting (including IPv6 and
  `(none)`), 180-second recent-handshake semantics, and the NTP warning.
- Preserve the settings parser's supported quoted assignments/comments without
  sourcing/evaluating shell code. Return only the current settings allowlist.
  Malformed metadata/settings must fail explicitly, not disappear from lists.
- Handle an interface disappearing during collection without producing a
  misleading partial-success response. Runtime counters are a near-time sample,
  not an atomic snapshot with unrelated procfs/sysfs metrics.

### 4.3 Metrics, JSON, and response parity

- Read procfs/sysfs directly for uptime, CPU counters, memory, interfaces,
  temperatures, and LED trigger state; use `getloadavg()` and `statvfs()` as
  appropriate. Preserve the existing metrics fields and LED semantics.
- Match `shutil.disk_usage()` semantics: total uses `f_blocks * f_frsize`,
  used uses `(f_blocks - f_bfree) * f_frsize`, and free uses
  `f_bavail * f_frsize`. Do not replace memory availability with `freeram`.
- Use 64-bit counters and filesystem arithmetic on ARM32, check overflow and
  allocation failures, and bound metadata size, peers, input strings, netlink
  buffers, response size, and request duration. Test 0-9 clients for this
  deployment, but do not introduce a new nine-client product limit or regress
  the existing address pool. Exceeding an implementation limit is an explicit
  error.
- Use a maintained JSON serializer (for example cJSON with an explicit
  Buildroot dependency), not scattered interpolated `printf` strings.
  Escape strings correctly and preserve integer counter precision; if cJSON
  is chosen, its double-based number representation needs an exact-integer
  strategy and tests. Do not silently change numbers into strings.
- Buffer the bounded JSON response before headers so failures can still return
  the correct status. Match content type, Content-Length, `no-store`, `nosniff`,
  Referrer-Policy, CSP, and the existing `{ok:false,error:{code,message}}` shape.
  Log sanitized error categories, never cookies, profiles, verifiers, or keys.
- Preserve route normalization, method checks, query rejection, authorization
  order, field names/types/units, nullable values, and documented missing-device
  behavior. Optional missing sensors are not equivalent to failed required I/O.

## 5. Frontend improvements without increasing device load

Keep sequential requests, page-aware polling, the 10-second baseline interval,
hidden-tab suppression, queued navigation, and the single in-flight guard.
Do not replace them with `Promise.all()` simply because readers can overlap.

- No transient failures were observed, so defer new backoff/jitter and cross-tab
  coordination unless follow-up tests show a need. Preserve explicit error
  reporting; never automatically replay mutations or show stale values as live.
- Preserve 401 handling, logout/pagehide cancellation, private-state/chart/QR
  clearing, and revalidation after history restoration. An aborted or superseded
  response must not repopulate private content.
- Preserve browser-side CPU/rate delta calculation and the 30-sample chart
  bound. Reset sampling after hidden periods, interface/counter resets, or
  nonpositive time deltas; retain counter precision within JavaScript limits.
- Consider a combined authenticated snapshot endpoint only if measurements show
  two native requests still dominate. That is a separately tested API extension,
  not a prerequisite for the drop-in optimization. Avoid caching secrets,
  adding a background collector, or introducing persistent metric history.

## 6. Authentication: preserve strength and compatibility

Keep 600,000 PBKDF2 iterations, random salts, constant-time comparison, existing
password rules, five-attempts-per-minute shared rate limiting, and cookie flags.
Reducing iterations to 25,000 is a 24-fold work-factor reduction, not a safe
performance tweak. It also breaks existing login: the current implementation
requires the stored verifier iteration count to equal `ITERATIONS`.

Measure target hashing time and inspect the deployed Python/OpenSSL crypto path
before considering a separate authentication change. Any future KDF migration
requires explicit approval, versioned verifier compatibility, bounded accepted
parameters, and tests for existing accounts and atomic upgrades. Do not combine
it with this performance rollout.

## 7. Build and permanent native deployment

1. **Baseline and contract:** retain the supplied measurements, use the simple
   repeat protocol above, and capture shared fixtures for current Python schemas,
   headers, errors, sessions, settings, and peers. Do not block implementation
   on a larger hardware benchmark matrix.
2. **Native implementation:** implement/test bounded parsers, session validation,
   locks, collectors, and JSON before changing the deployed CGI entry point.
3. **Buildroot integration:** add a reproducible local package/source and explicit
   dependencies; build with the VPN Buildroot ARM/uClibc toolchain, not the
   SDK's unrelated Rockchip libc. Enable supported hardening/compiler warnings.
   Avoid committing host or prebuilt target binaries.
4. **Image wiring:** ensure the final CGI has executable/root-owned permissions
   and is not overwritten by the overlay's old shell script. Wire final install
   ordering explicitly: the existing project post-build hook runs before
   overlays, so installing there alone is insufficient. Verify final image
   binary, loader, shared libraries, and `S49httpd` initialization.
5. **Compatibility and board qualification:** run the tests below, then flash
   and repeat the same baseline scenarios. QEMU/host checks do not prove
   hardware netlink behavior, memory safety under load, or latency.
6. **Enable and document:** the observed board results led to user approval
   of permanent native dashboard routing. Remove obsolete selector/legacy CGI
   files during incremental image assembly, retain root ownership validation,
   and update [WG_GUI_IMPL.md](./WG_GUI_IMPL.md). Credentials, sessions, CLI data
   and on-disk VPN formats remain unchanged. Runtime backend rollback is no
   longer available; reverting requires a previous firmware version while
   preserving persistent data.

## 8. Validation and provisional acceptance criteria

Reuse/extend the existing
[unit tests](./sysdrv/tools/board/buildroot/tests/test_vpn_web.py),
[HTTP tests](./sysdrv/tools/board/buildroot/tests/test_vpn_web_http.py), and
[service tests](./sysdrv/tools/board/buildroot/tests/test_vpn_web_service.py).
The HTTP suite uses the native front controller for all requests. Retain
global-gate tests for cold routing and explicit native-read bypass/concurrent-reader tests.

Required coverage:

- Differential Python/native fixtures for success/error payloads, headers,
  settings quoting, interface down/up, disabled peers, absent endpoints, zero/
  missing counters, 64-bit values, IPv6 endpoints, and malformed input.
  Freeze clocks/counters in fixtures rather than comparing moving live values.
- Missing/duplicate/invalid cookies; missing auth config; fractional issue times;
  exact expiry boundary; future/nonfinite timestamps; symlink/permission/I/O
  failures; reboot; setup/login/logout races; and no polling lifetime extension.
- Netlink fragmented/multipart peers, malformed attributes, interrupted dumps,
  kernel errors, timeouts, disappeared interfaces, and maximum-size fixtures.
  Run host parser/serializer tests with sanitizers where supported.
- Two concurrent readers plus representative reader/writer and auth/logout
  races in isolated fixtures/integration tests. Verify no deadlock, excessive
  memory, falsely successful responses, leaked locks, or duplicate mutations.
  Backup/restore and destructive client tests belong in fixtures or a disposable
  environment, not the user's live-client performance run.
- Real BusyBox HTTP tests must execute the built native CGI, not a stub that
  bypasses native authentication/netlink. Use target/QEMU checks for ABI and
  final board tests for real kernel data; audit hot paths for helper execution.
- Browser smoke checks: all pages/actions, themes, rates, visibility changes,
  busy/stale states, QR/download behavior, failed logout, and history restoration.

Initial engineering targets below are **unverified goals**, not predicted
results. The one-client idle/active runs are the primary board acceptance test;
repeat a fully visible idle baseline before making final improvement claims.

| Measure | Target / acceptance gate |
|---|---|
| Hot-read helper processes | No Python or utility execution from native `status` or `clients`; `state` may remain Python. |
| Complete-refresh latency, one client | Aim for p95 <=600 ms idle and <=2000 ms with comparable VPN traffic: over 3x faster than the supplied provisional p95 values. Reassess relative gains against the matched visible-tab baseline. Report endpoint timings too; do not promise 1-3 ms. |
| Whole-system CPU | Aim to reduce idle polling-enabled CPU at the same cadence; report the matched before/after average. Do not claim a percentage reduction in per-request CPU from browser/whole-system averages. |
| Errors and concurrency | Zero observed errors in both normal runs; no request-gate HTTP 503 from native-reader/native-reader contention in integration tests. Auth/VPN writer conflicts remain explicit and bounded. |
| Memory | Aim to retain >=30 MiB minimum sampled MemAvailable in the normal one-client runs, versus the supplied 34.3 MiB. This is a provisional headroom goal, not a peak-memory guarantee; investigate any decline or OOM evidence with process-level measurements. |
| VPN impact | Normal client traffic remains usable and comparable workload byte rates/download speeds show no unexplained regression. These runs cannot establish a throughput ceiling, a 5% non-regression bound, or packet-loss equivalence; use a separate controlled test if those claims are needed. |
| Compatibility | Required fixtures/integration checks pass; all existing credentials/data still work. The approved permanent-routing cleanup removes runtime legacy rollback, not persistent-data compatibility. |

Do not label the optimization complete until target-board measurements and
remaining exceptions are recorded. If targets are missed, profile the failing
phase before adding caching, parallel polling, or a resident service.

## 9. Test code used in user's own browser on the live board

```js
(() => {
  const label = "idle"; // Change to "vpn-active" for the second run.
  if (window.stopVpnBaseline) throw new Error("A measurement is already running.");

  const originalFetch = window.fetch;
  const requests = [], refreshes = [], system = [], notes = [];
  let active = true, pendingStatus = null;
  let hidden = document.hidden;
  const started = performance.now();

  const visibility = () => { hidden ||= document.hidden; };
  document.addEventListener("visibilitychange", visibility);

  function wrappedFetch(...args) {
    const input = args[0];
    const url = new URL(input instanceof Request ? input.url : input, location.href);
    const route = url.origin === location.origin
      ? /^\/cgi-bin\/vpn\.cgi\/(status|clients)$/.exec(url.pathname)?.[1]
      : null;
    const start = performance.now();
    const promise = originalFetch.apply(this, args);

    if (route) {
      promise.then(response => {
        response.clone().json().then(data => {
          if (!active) return;
          const end = performance.now();
          const ok = response.ok && data.ok === true;
          requests.push({
            route, ms: end - start, http: response.status,
            ok, error: ok ? null : data.error?.code || "unspecified"
          });

          if (route === "status") {
            pendingStatus = ok ? {start, end} : null;
            const m = data.metrics;
            if (ok && m) system.push({
              uptime: m.uptime, total: m.cpu.total, idle: m.cpu.idle,
              available: m.memory.available,
              wgRx: m.networks.wg0?.rx, wgTx: m.networks.wg0?.tx
            });
          } else {
            if (ok && pendingStatus && start - pendingStatus.end < 2000) {
              refreshes.push(end - pendingStatus.start);
            }
            pendingStatus = null;
          }
        }).catch(error => {
          if (active) notes.push(`${route}: response measurement failed (${error.name})`);
        });
      }, error => {
        if (active) requests.push({
          route, ok: false, http: null, error: error.name
        });
      });
    }
    return promise;
  }

  window.fetch = wrappedFetch;

  function timings(values) {
    const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
    const percentile = p => sorted.length
      ? Math.round(sorted[Math.ceil(sorted.length * p) - 1]) : null;
    return {
      samples: sorted.length,
      p50_ms: percentile(0.5), p95_ms: percentile(0.95),
      max_ms: sorted.length ? Math.round(sorted[sorted.length - 1]) : null
    };
  }

  const timer = setTimeout(stop, 310000);

  function stop() {
    active = false;
    clearTimeout(timer);
    if (window.fetch === wrappedFetch) window.fetch = originalFetch;
    document.removeEventListener("visibilitychange", visibility);
    delete window.stopVpnBaseline;

    const first = system[0], last = system[system.length - 1];
    const ticks = first && last ? last.total - first.total : 0;
    const elapsed = first && last ? last.uptime - first.uptime : 0;
    const available = system.map(s => s.available).filter(Number.isFinite);
    const transfer = key => elapsed > 0 &&
      Number.isFinite(first[key]) && Number.isFinite(last[key]) &&
      last[key] >= first[key] ? last[key] - first[key] : null;

    console.log(JSON.stringify({
      label,
      duration_seconds: Math.round((performance.now() - started) / 1000),
      tab_was_hidden: hidden,
      status: timings(requests.filter(r => r.route === "status" && r.ok).map(r => r.ms)),
      clients: timings(requests.filter(r => r.route === "clients" && r.ok).map(r => r.ms)),
      complete_refresh: timings(refreshes),
      failures: requests.filter(r => !r.ok),
      system_cpu_average_percent: ticks > 0
        ? +(100 * (1 - (last.idle - first.idle) / ticks)).toFixed(1) : null,
      minimum_sampled_available_memory_MiB: available.length
        ? +(Math.min(...available) / 1048576).toFixed(1) : null,
      vpn_counter_interval_seconds: elapsed,
      vpn_rx_bytes: transfer("wgRx"),
      vpn_tx_bytes: transfer("wgTx"),
      notes
    }, null, 2));
  }

  window.stopVpnBaseline = stop;
  console.log("Measuring existing dashboard polls for 5 minutes. Keep this tab visible.");
  console.log("To finish early: stopVpnBaseline()");
})();
```