# Installer and macOS source audit

Baseline: `c0525a74c35fd74c815326d957c21a593a6aaccb`; reviewed on 2026-11-01.
This is a source review, not a certification of downloads, installed privileges,
macOS PF behavior, or live ExitLag compatibility. Line references refer to the
baseline. All tracked files under `installers/` and `macos/`, including build
scripts, import/export declarations, maps, SVG assets, and tests, were read.

## Subsystem inventory and assessment

| Subsystem | Purpose and dependencies | Implemented | Incomplete / compatibility limits |
| --- | --- | --- | --- |
| `installers/setup.py`, `bridge_setup/{core,util}.py`, `__init__.py`, `catalog.json` | Per-user setup, private records, pinned HTTPS assets; Python 3.10+, curl, Wine 11.17 | Digest-verified downloads; bounded archive member count/expanded bytes; traversal/device/link checks; ownership markers; setup flock; interactive user-supplied vendor installer; dedicated prefix; backup/repair/preserve-account uninstall | No signature validation of user-selected installer (PE shape only); download byte/time bound is time + digest, not catalog `size`; runtime upgrade requires explicit future implementation; no supported arbitrary Linux architectures |
| `bridge_setup/pe.py` | PE imports/exports gate using Python struct parser | Bounded sections/import counts, file-backed RVA checks, missing exported-name rejection | Export presence does not prove ABI/calling convention/behavior; malformed modules silently ignored; duplicates `macos/pe_check.py` |
| `installers/build_runtime.py` | Pinned Zig/Wine/Python source and runtime builder; patch, make, clang, tar/xz | Pinned SHA256, patch revision marker, source archive, binary home-path scan, manifest | Caches keyed largely by names, partial source-extraction/build recovery needs tests; source gzip metadata not fully normalized, reproducibility unmeasured; large download/build not executed here |
| `linux/{app.py,run_root.py}` | Tk desktop setup, polkit fixed root supervisor; `/proc`, pkexec, root-owned installation | Wine as normal user; process start-time checks; data-only map snapshot; private map and lease; root environment allowlist; six-second lease | Desktop starts TCP backend only; manual exact mapping required; shared backend fixed ports/runtime imply single active host session; lifecycle findings below |
| `linux/{build.py,install.sh,uninstall.sh}` | Debian and portable installation; dpkg, root install, desktop entry | Symlink rejection, fixed installation paths, ownership, executable flags, account-preserving removal | Build requires Debian dpkg even for portable archive; upgrade not transactionally rolled back after desktop-file failure; package verification across actual Arch/Ubuntu unavailable here |
| `macos/{bridge.py,pf_plan.py}` | EXL1 v3 TCP user-space proxy, optional scoped PF; libproc, lsof, PF | Exact executable path and socket-local tuple attribution; bounded 64 active flows; token authentication; loopback-only callback redirect; direct fallback; transfer counters | IPv4 TCP only; no UDP/IPv6; global per-peer callback serialization; process scan and lsof per flow; no UID check in NativeIdentity.owner; no TCP close callback implementation |
| `macos/{auto_service,auto_common,entry}.py` | Installed root launchd helper, UID-specific lease and status | Fixed immutable code entry, private bounded records, epoch, root-owned runtime, owned PF anchor/reference, crash-start cleanup | Fixed two WoW destinations and two exact maps; cleanup fault propagation and telemetry semantics below; no reboot/sleep evidence from this session |
| `macos/{auto_agent,companion,wine_socket}.py`, `wine-socket-companion.c` | User-owned real-game-associated Winsock source tuple companion | Native exact executable detection, game-bound heartbeat, token, ports 51902/51903, per-flow config reload, bounded native workers | Specific WoW paths/identities only; parent PID liveness lacks generation identity; config loader lacks O_NONBLOCK; no cross-UID MAC attribution policy; native helper build/live validation not performed |
| `macos/{session,supervisor,recover,control_probe,doctor}.py`, `client.sh` | Legacy reviewed foreground PF sessions, read-only diagnostics and probes | Narrow anchor generator, explicit apply, token auth, recovery owner/anchor validation, no automatic account or vendor downloads | Legacy scripts must not run beside installed app; legacy root executes checkout Python after sudo; supervisor PF cleanup failure ignored; diagnostics not a compatibility proof |
| `macos/{build-shim,build-companion}.sh`, `driver-registration.cpp`, `pe_check.py` | Cross-compiled PE helper and nfapi shim; Zig/MSVC target | Driver management explicitly unsupported; opt-in Qt import patch; shared nfapi source | Version-sensitive Qt IAT workaround; no runtime ABI proof; duplicated PE parser; companion backend is synthetic Winsock process tied to real native process, not a game implementation |
| `macos/app/{ExitLag.swift,build.sh,sign_payload.py,notarize.py,make-icon.swift,BridgeIcon.svg}` | Swift menu launcher, package, root helper install; AppKit/SwiftUI/Xcode/pkgbuild/codesign | Private status validation, isolated Python, fixed root launch daemon, optional Developer ID and notarization workflow, original assets | Only single installation user, arm64 distribution evidence inherited only; unsigned beta; no Apple build/sign/notary executed here; upgrade/uninstall recovery edge cases need host validation |
| `macos/games.{auto,example}.map` | Exact native-to-Windows identity allowlist | Classic Era / Forever explicit game paths | Cannot generalize to arbitrary games or alternate installation paths without explicit verified mappings |
| `macos/test_*.py` | Auth, loopback byte forwarding, PF-plan, private files, restart/fallback tests | 33 discovered tests in baseline | PF parser test unconditionally invokes macOS-only binary; 18 loopback tests need socket permission in this cloud sandbox; tests do not establish game routing |

Licenses and notices are preserved. README claims of previous live tests are
maintainer-provided historical statements, not reproduced evidence in this audit.

## Confirmed findings

### INST-01 — medium: desktop misreads UTF-16 tasklist output

Evidence: `installers/linux/app.py:189-192` checks `b'exitlag.exe'` in raw stdout.
`installers/bridge_setup/core.py:25-31` already handles Windows console UTF-16 and
uses it in `Setup.command` at line 139. For an existing client,
`b'exitlag.exe' not in 'ExitLag.exe'.encode('utf-16le')` is true. A successful
tasklist with this encoding triggers `client_closed`, lease removal, client
termination and window destruction. This is a deterministic encoding-path defect;
the live tasklist encoding of the pinned Wine is not measured here.

Recommendation: reuse shared `console_output()` and test UTF-8, BOM/BOM-less
UTF-16LE, UTF-16BE, absent process and unsuccessful tasklist. Test the actual
desktop decision helper without requiring Tk display, Wine or root.

### INST-02 — medium: desktop cleanup can stop midway on taskkill timeout

Evidence: `installers/linux/app.py:199-210`: lease is removed first (good), but
`subprocess.run(...timeout=15)` at 203 can raise before `client`, `helper` and lock
are reset. `close()` then fails before destroying the window. Timer polling also
calls this path. No test exercises timeout/error cleanup.

Recommendation: tolerate `OSError`/`TimeoutExpired` while always releasing the
local session lock in `finally`; continue relying on removed lease to stop the
privileged supervisor. Avoid broad process killing. Record cleanup uncertainty.

### INST-03 — medium: user-controlled future timestamp keeps lease accepted

Evidence: `installers/linux/run_root.py:49-56` only checks
`time.time() - info.st_mtime < 6`, so future timestamps satisfy freshness. This
does not cross the authorization boundary: the same user already requested
routing, and parent UID/starttime is checked independently at 81/112. It weakens
the documented six-second fail-open lease guarantee during a stalled parent.

Recommendation: require `0 <= age < 6`, preferably use monotonic observation of
changed record stamps for lease bookkeeping as the macOS service does. Include
future mtime, wrong owner, FIFO, hardlink and timestamp-boundary tests.

### INST-04 — medium compatibility gate: malformed client modules are ignored

Evidence: `installers/bridge_setup/pe.py:68-74` and identical
`macos/pe_check.py:68-74` ignore all parser errors if at least one other module
has recognized imports. A future client layout may be partially unchecked while
still reporting all required exports present. The check also compares only
names, not structure layouts, ordinals supplied by shim, or callback behavior.

Recommendation: make parse failures explicit in diagnostics, define which
modules must parse, distinguish unsupported/check-incomplete from compatible,
share parser implementation, add bounded malformed and ordinal test fixtures.

### INST-05 — medium: root companion loader can block on FIFO

Evidence: `macos/wine_socket.py:19` opens a user-owned config with O_NOFOLLOW but
without O_NONBLOCK. The normal path is in the user's state directory. Replacing
it with a FIFO blocks before fstat rejects it. In the installed architecture
this blocks a bounded flow worker (capacity 64), rather than the entire control
loop, but enough stale FIFOs exhaust proxy capacity. Contrast private record
loaders in `auto_common.py:15` and `installers/bridge_setup/util.py:41`.

Recommendation: O_NONBLOCK on private config opens, nlink==1 validation, tests
for FIFO/symlink/hardlink/oversize malformed configurations. Treat same-user
token/config compromise as within the user's session trust boundary.

### INST-06 — medium availability: macOS cleanup failure interrupts later cleanup

Evidence: `macos/auto_service.py:121-127` calls `disable()` before closing bridge
and unlinking tokens; `disable()` propagates pfctl failure at 117/119. The error
handler calls `session.close()` at 195 with no additional protection, so a
second cleanup failure exits the service. launchd KeepAlive and startup fixed
anchor cleanup mitigate, but PF state remains until successful recovery.
`macos/supervisor.py:116-130` instead ignores cleanup return codes and deletes
state, reducing recoverability after failed PF deletion.

Recommendation: independent cleanup stages with retained recovery evidence and
explicit unsuccessful-cleanup status; mock pfctl failures, then validate on Mac.

### INST-07 — low: macOS PF test breaks generic Linux discovery

Evidence: `macos/test_pf_plan.py:8-13` runs `/sbin/pfctl` unconditionally, unlike
`test_bridge.py`'s guarded native attribution test. Debian has no pfctl.

Recommendation: platform/dependency skip only on the parser check; keep pure
PF-plan validation running on Linux. A missing native OS facility is SKIP, not
PASS, and must not mask malformed generated rules on a Mac with pfctl.

### INST-08 — medium privilege scope: macOS process owner attribution lacks UID

Evidence: `macos/bridge.py:112-139` matches executable and local source endpoint
using libproc/lsof, without checking the owning UID. PF rules scope outbound
routing to configured UID, but loopback `rdr` lacks UID restriction
(`pf_plan.py:20`), and a proxy connection must not acquire another user's exact
game identity solely by collision/reuse of local tuples. No exploit established;
the omission and stronger-than-needed global PID scan are confirmed.

Recommendation: pass authorized UID into attribution, check kernel process UID
and generation around socket ownership, test multi-user/reused-port cases in an
isolated Mac test host. Do not claim an exploit without reproduction.

### INST-09 — low: relay status counts selected active flows before bytes

Evidence: `auto_service.py:200` computes relay_active from active+relay booleans;
`auto_agent.py:209-210` and `app/ExitLag.swift` label this as traffic flowing.
`bridge.py:416-419` marks relay after connect, while byte counters update only at
443-449. A connected but idle relay can produce the traffic-flow label. This is
not evidence of stable bidirectional gameplay.

Recommendation: separate connected redirect, observed sent bytes, observed
received bytes and human gameplay verification in status/schema/reporting.

### INST-10 — low: duplicate parsers and hardcoded platform policy

`macos/pe_check.py` duplicates `installers/bridge_setup/pe.py`; default_state
reappears across Python/Swift; fixed game scopes are embedded in auto_service,
companion, UI and maps. Avoid large rewrite: first consolidate pure PE parsing
and lifecycle decision helpers with regression coverage, while keeping immutable
installed root entry points isolated from user packages.

## Hypotheses / additional validation needed

- Archive extraction validates links and size before extraction, but TOCTOU via
  a hostile ancestor directory and partial-cache recovery need adversarial
  testing. Verified SHA256-pinned archives and user-only setup reduce exposure;
  no arbitrary extraction exploit was established.
- `core.validate_installer()` validates shape and size, not Authenticode or
  vendor identity. User-selected trusted download is the existing contract;
  do not silently claim the chosen executable is authentic.
- Root-code immutability is checked on installation root and ancestors in
  Linux run_root; nested source/binary ownership is assumed from packaging.
  Test tampered nested files before deciding whether stronger validation helps.
- SIGKILL of supervisor/backend or failed nft/PF deletion cannot be recovered by
  Python finally/traps alone. Linux backend ownership/cleanup is audited by the
  backend reviewer; verify crash recovery in isolated privileged namespaces.
- Mac NativeIdentity scans every PID and invokes lsof per allowlisted process
  per connection; shared peer lock serializes 300 ms callbacks. These are code
  bottlenecks, not measured performance regressions.
- Companion parent checks compare PID liveness or executable path, not process
  generation. PID reuse races and malicious same-UID path substitution require
  dedicated tests. Linux installed supervisor already includes starttime.
- Python 3.14 tarfile defaults differ; existing code warns on Python 3.12. Test
  pinned Python and distro Python versions with valid internal archive links.
- Release source gzip timestamp normalization, archive hardlinks and runtime
  dynamic-library compatibility need reproducible builds on Arch and Ubuntu.
- No current test demonstrates NetworkManager/systemd-resolved/VPN coexistence,
  actual macOS multi-user PF scope, sleep/wake, or real ExitLag update behavior.

## Tests executed by this reviewer

On Debian 13, unprivileged Python 3.12, default cloud sandbox:

| Command | Actual result |
| --- | --- |
| `python3 -m unittest discover -s tests -p 'test_installer.py' -v` | PASS: 13 tests; tarfile Python 3.14 migration warning |
| `python3 -m unittest discover -s tests -p 'test_linux_desktop.py' -v` | PASS: 5 tests |
| `python3 -m unittest discover -s tests -p 'test_mac_distribution.py' -v` | PASS: 4 tests |
| `python3 -m unittest discover -s macos -p 'test_*.py' -v` | 33 run: 13 pass, 19 errors, 1 skip. 18 errors are denied socket creation (`EPERM`); one is missing `/sbin/pfctl`; native libproc case correctly skipped |

The socket restriction is the command sandbox, not proof the managed host
cannot run loopback tests. Rerun permitted loopback checks with the supported
network permission mechanism; do not bypass sandbox or claim these attempts
passed. Mac build/install/PF, fresh pinned Wine and live account/game tests are
NOT TESTED here. Root owns the consolidated final baseline report.

## Recommended incremental order

1. Fix Linux tasklist encoding and always-complete desktop cleanup; add headless
   regression tests with synthetic subprocess output/timeouts.
2. Enforce Linux lease time bounds and nonblocking private-file reads; add
   malformed/private file boundary tests before touching routing behavior.
3. Make test platform prerequisites explicit and establish portable CI runner.
4. Improve PE gate diagnostics/module completeness without loosening checks.
5. Harden root cleanup failure reporting/recovery with privileged isolated tests.
6. Generalize discovery/routing only after kernel attribution and genuine ExitLag
   callback decisions have evidence. Preserve macOS functionality and notices.

## Implemented corrections after the audit gate (2026-11-02)

- INST-01: Linux tasklist liveness now normalizes stdout with shared
  `console_output()`. The existing threaded probe is a separately testable
  method. Synthetic subprocess fixtures cover UTF-8, UTF-16LE with/without BOM,
  UTF-16BE with BOM, confirmed absence and uncertain/error results.
- INST-02: Expected Wine taskkill timeout/OSError no longer interrupts local
  session cleanup. The lease is removed before invoking Wine; local lock and
  session references are always released. Client termination failure remains
  explicit in the UI. This does not prove privileged firewall deletion.
- INST-03: The Linux root supervisor requires lease age `0 <= age < 6`;
  future timestamps, exactly expired timestamps, wrong UID, public modes,
  hardlinks and FIFOs are rejected by regression tests. Backwards clock jumps
  intentionally stop rather than extend routing authorization.
- INST-05: Mac companion configuration opens are nonblocking and reject
  multiple hardlinks. A real FIFO is validated without waiting for a writer;
  the test checks O_NONBLOCK before allowing the open to avoid test hangs.
- INST-07: Only the actual macOS PF-parser test is skipped on non-Darwin hosts;
  pure plan validation remains active. A missing/broken pfctl on Darwin is a
  failure, not a silently skipped check.
- The Linux root map validator and editor now match the backend's security
  correction: native mappings use two columns, prefix mappings require the
  canonicalizable existing regular executable loader in a third column.
  Prefix directories and executable types/permissions are checked, canonical
  duplicates rejected, and legacy two-column prefix entries require migration.
  This reduces environment-only impersonation; it does not authenticate an
  individual Windows executable inside a shared allowlisted prefix.

Reviewer rerun:

```sh
python3 -m unittest discover -s tests -p 'test_linux_*.py' -v
```

Result: **16 PASS** (11 supervisor, 5 headless launcher), no skips/failures.
Root independently reports the same 16 passing cases and a permitted-loopback
macOS run of **35 tests: 33 PASS, 2 SKIP** (macOS PF parser and libproc identity).
The reviewer's attempted additional-permission network invocation was stopped
without results and is not counted as passed. Consult the consolidated root
testing report for executed commands and retained evidence. Native Mac
PF/install/build and live game behavior remain unverified in this environment.

Outstanding: INST-04, INST-06, INST-08, INST-09 and the broader hypotheses above
remain audit findings; no full macOS architectural rewrite was attempted.
