# Shim and Wine compatibility audit

Baseline: `c0525a74c35fd74c815326d957c21a593a6aaccb`. All references below describe
that baseline, before remediation. Source inspection, not live ExitLag evidence.

## Complete assigned inventory

| File | Purpose / dependencies |
| --- | --- |
| `shim/nfapi/nfapi_stub.cpp` | 2,290-line freestanding x64 PE DLL: reconstructed NetFilter C++ ABI, trace, main-image IAT guards, optional synthetic experiments, Winsock IPC, TCP/UDP callback adaptation, PID translation. Imports kernel32, ws2_32, iphlpapi. |
| `shim/nfapi/build.sh` | LLVM `clang-cl`, `lld-link`, `llvm-dlltool` x86_64 build; no CRT, exceptions, RTTI or stack-cookie runtime. |
| `shim/nfapi/kernel32.def` | Import-library declarations for kernel32 functions used by the shim. |
| `shim/nfapi/ws2_32.def` | Winsock import-library declarations. |
| `shim/nfapi/iphlpapi.def` | TCP and UDP owner-table API imports. |
| `shim/nfapi/iphlpapi-missing.def` | Missing-import crash-guard synthetic executable import. |
| `shim/nfapi/powrprof.def` | Missing-import crash-guard synthetic executable import. |
| `shim/nfextlag/nfextlag_stub.c` | Presence-only Wine driver service entry point; returns success, no device, dispatch functions or packet filtering. |
| `shim/nfextlag/nfextlag.rc` | Stand-in driver version resources, currently `1.7.1.6`; maintenance dependency on client expectations. |
| `shim/nfextlag/build.sh` | Builds native x64 PE driver image with LLVM resource compiler and linker. |
| `wine-wbemprox/build-local.sh` | Pinned Wine 11.17 source revision and exact installed Wine Staging version; builds one WMI DLL and constructs local module staging, preserving system DLL hash. Requires installed `/usr/lib/wine` layout. |
| `wine-wbemprox/patches/0001-wbemprox-add-logicaldisk-root-directory.patch` | Wine LGPL patch implementing the missing logical-disk/root-directory WMI association; no full Wine source or proprietary client included. |

All assigned files were read completely. Related protocol, ABI checks, synthetic
tests and existing provenance/guard documentation were also read for cross-checks.

## Implemented boundaries

- Production supports the selected export table, not the entire NetFilter SDK
  (`nfapi_stub.cpp:329`). Unknown status exports fail explicitly.
- Real production callbacks include TCP connect-request and UDP created,
  connect-request, datagram and closed events (`:1575–1810`). The transport does
  not synthesize a redirect decision: it records what the registered callback
  actually mutates or posts.
- TCP connected/closed are available only to explicit synthetic injection
  (`:1054–1074`), not to the native transport.
- UID/token verification is performed by the native helper; the shim reads the
  token anew on each reconnect and sends it in HELLO (`:1840–1928`). It does not
  authenticate a server before disclosing the token.
- UDP post/state messages are serialized against other writes with an atomic
  send lock (`:1378–1401`); nested per-event bookkeeping is a single global
  context (`:1299–1304`, `:1645–1654`). This is not concurrent callback support.
- Missing Windows features return unsupported through eleven unconditional
  main-executable IAT guards (`:547–559`, `:613–697`). PC Boost/DNS optimization
  are not implemented Linux features.
- `nf_setRulesEx` returns success but only traces the rules (`:2177–2190`), and
  flow-control handle allocation does not implement shaping (`:2075–2089`).
  These are compatibility accommodations, not a kernel filter-rule engine.

## Confirmed findings

| ID / severity | Evidence | Consequence and recommendation |
| --- | --- | --- |
| SHIM-01 / High reliability, memory safety | `ipc::stop` only sets a flag (`:1999`); `nf_free` does not close/wake/join workers or clear handler (`:2221–2225`). `ipc::start` discards thread handle and permits another start (`:1991–1996`). Injection likewise discards the live handle on stop (`:1182–1186`). | A blocked read, retry sleep, callback or injection sleep can survive `nf_free`; immediate re-init can re-enable the old thread and create multiple readers/callback callers against shared buffers and handler state. Define an explicit state machine, retain handles, cancel/wake, join before returning and prevent duplicate init. Add Wine mock init/free/re-init under load. No live reproduction claimed. |
| SHIM-02 / Medium security and correctness | `parse_endpoint` (`:1813–1832`) never bounds octets, accepts empty nonfinal octets, truncates integer overflow, permits arbitrary IPv4 and ignores trailing port characters. HELLO then sends a session token (`:1922–1928`). | Typo/malformed configuration can silently connect to a different address or a nonlocal listener. Restrict the documented transport to exact numeric loopback IPv4, reject malformed/overflowed input and keep the documented default port. Pure native tests can exercise the exact parser without Wine. |
| SHIM-03 / High memory safety at the IPC boundary | `resolve_linux_pid` verifies a minimum fixed reply header, then copies `reply->path_length` without checking that those bytes exist in the frame (`:1365–1373`). | A malformed server response can copy stale static-buffer content; with sufficiently large caller buffer it can read beyond the static buffer. Validate trailing length before copying, validate flags/reserved fields and decode the documented UTF-8 rather than widening bytes. Malicious-server reachability depends on the loopback/server trust model; not an arbitrary remote exploit claim. |
| SHIM-04 / Medium compatibility | IPC definitions duplicate `backend/protocol.h` (`:1204–1292`), outer receive buffer is 65,536 (`:1939–1944`) while backend permits 131,072; a UDP request header alone is 92 bytes. Nested resolver independently uses 65,536 (`:1362`). | Valid UDP payloads above 65,444 bytes with no options force disconnect. A maximum non-jumbo IPv4 UDP payload is 65,507 bytes. Share the protocol header/constants and compile-time packed-size assertions; test boundary-sized synthetic frames. Do not broaden active UDP routing from this alone. |
| SHIM-05 / High attribution correctness | `owning_windows_pid(local, remote)` never reads its remote argument; IPv4 and IPv6 select the first TCP owner matching local address/port (`:1478–1507`). UDP wildcard resolution similarly selects a last matching owner (`:1517–1554`). | Reused source ports across different remote peers or ambiguous owner tables can name a different process. Match full TCP tuple and verify table bounds; fail closed on ambiguous UDP ownership. Test duplicate local tuples, remote scopes and wildcard ties. Actual wrong-game interception not reproduced. |
| SHIM-06 / Medium protocol/security | Outer frame processing accepts events before any HELLO_ACK, and neither receive loop validates `flags` (`:1359–1375`, `:1939–1980`). Fixed records accept trailing bytes with `>=`. | A fake/stale/malformed listener can dispatch callbacks before protocol negotiation or smuggle reserved fields. Require one accepted ACK before dispatch, exact fixed lengths, recognized families/directions and zero reserved flags. Introduce these checks without fabricating callback outcomes. |
| SHIM-07 / Medium identity/lifecycle | A 128-entry global numeric Linux PID ring has no process-start-time, expiry or connection-reset semantics (`:1306–1323`). UDP cache is a collision-overwriting 1,024-entry id map and does not remove closed entries (`:1559–1573`, `:1656–1696`). | Linux/Windows PID numeric collisions and PID reuse can resolve an unrelated identity; reconnect can retain stale origins. Carry origin and birth identity with endpoint state, expire on close/session reset, test overflow and PID reuse. |
| SHIM-08 / Medium compatibility | IAT walker compares unbounded C strings after only proving a single byte valid (`:658–680`). It patches every listed import even if a future Wine provides a working implementation. `InitializeIpInterfaceEntry` and other void APIs are replaced by no-op unsupported thunks (`:573–590`). | Out-of-range PE strings can cross image bounds, and newer Wine retains missing behavior even once supported. Bound string comparison to image/RVA span; test synthetic malformed PE images; evaluate guard necessity against the actual runtime. Void routines cannot convey an unsupported status to the caller. |
| SHIM-09 / Medium performance/privacy | Many trace payloads are formatted and dereferenced even when `out.enabled=false`; enabled `finish` opens, flushes and closes each log line (`:434–471`). Explicit research operations scan/dump client memory (`:889–1012`) and payload traces include bytes (`:1777–1778`). | Formatting/OS queries impose unmeasured overhead; opt-in research data can contain account/private configuration. Keep research off by default, avoid formatting when disabled, bound/secure log destinations, and exclude raw output from delivery. Benchmark before claiming performance improvement. |
| SHIM-10 / Medium resource/error handling | `WSAStartup`/`setsockopt` return values ignored (`:1899–1919`); no `WSACleanup`; `g_socket` is assigned before token read but not reset on the no-token `continue` (`:1920–1929`); init succeeds even if worker creation fails (`:2217`). | Missing token leaves a stale closed socket visible to exports until the next attempt; creation failure looks initialized; timeout setup failure can remove expected bounds. Check every setup result, clear socket in one cleanup path and pair runtime resources with lifecycle state. |
| WINE-01 / Medium portability | Local wbemprox build pins Wine Staging 11.17, exact SHA and `/usr/lib/wine` tree; config/build reuse keys only on Makefile existence (`build-local.sh:7–28`, `:51–57`). | Ubuntu, alternate Wine packaging and updates cannot be assumed to work; a stale build configuration may be reused. Preserve pin as a known target; add explicit runtime/build manifest and package-layout probes before widening. Build artifacts remain local, not system overrides. |
| ABI-01 / Medium compatibility | Manually reconstructed packed structs/vtable slots, x64-only build, no runtime callback contract negotiation. Presence-only driver hard-codes version `1.7.1.6`. Export checking covers names, not callback layout/semantics. | Client/Wine updates may preserve export names but change behavior or ABI. Add compile-time layout assertions, shared wire definitions, synthetic callback-provider tests, client/Wine version manifests and explicit live validation gates. Preserve third-party notices and the existing unresolved interface provenance statement in `THIRD_PARTY.md`. |

## Verified parser reproduction

The actual baseline `parse_endpoint` function was extracted mechanically into
`/tmp/exitlag-shim-endpoint-baseline.cpp` and compiled without modification with
`g++ -std=c++17 -Wall -Wextra -fsanitize=address,undefined`. This is an ad-hoc
baseline reproduction, not a permanent regression test or Windows ABI test.

| Input | Observed baseline result |
| --- | --- |
| `127.0.0.1:51900` | accepted |
| `192.0.2.1:51900` | accepted (non-loopback) |
| `127.0.0.999:51900` | accepted as `127.0.0.231` |
| `127.0.0.1:51900garbage` | accepted |
| `127..0.1:51900` | accepted as `127.0.0.1` |
| `4294967423.0.0.1:51900` | accepted as `127.0.0.1` after unsigned wrap |

Executed successfully with `ASAN_OPTIONS=detect_leaks=0`; the default run failed
because LeakSanitizer cannot operate under this sandbox's ptrace restrictions.
Leak checking is **SKIPPED**, not passed. No session token or real client was used.

## Hypotheses requiring new evidence

- ExitLag may require production `threadStart`/`threadEnd` notifications: those
  only exist in the synthetic-injection thread (`:1140–1171`), whereas production
  IPC invokes callbacks without them. Compare real callback threading contracts
  before adding events.
- Rules that return success but are not enforced and missing TCP connected/closed
  callbacks may explain some detected-but-not-routed games. Need a client build,
  selected legitimate game profile, unmodified callbacks and actual traffic to
  distinguish missing profile, wrong identity, unmatched server address, missing
  event and absent redirect decision.
- Research `VirtualQuery` checks are not protection against concurrent unmapping;
  the normal event-handler object is trusted in-process data. No race exploit or
  client-memory crash was demonstrated.
- Worker/global UDP context races become likely with asynchronous client calls;
  the client's actual threading behavior and thread ownership need traces from
  an explicitly consented local synthetic/live experiment.

## Incremental architecture and acceptance criteria

1. Extract a tiny freestanding validation helper for loopback endpoint parsing
   and PID-reply length validation. Native C++ tests cover defaults, boundaries,
   malformed frames, large lengths and canaries. Preserve x64 PE ABI and callback
   semantics; no routing-policy expansion.
2. Share the wire header and add size/layout assertions in Linux and PE builds;
   extend synthetic tests up to the permitted frame limit. No commercial binary
   needed for this stage.
3. Introduce a transport session owner with bounded teardown; only then separate
   callback adaptation, process attribution and research features. Prove repeated
   init/free/re-init with a mock DLL callback consumer under Wine.
4. Scope process identity to a verified flow/session lifetime and compare full
   owner tuples. Unit-test ambiguous ownership before broader interception.
5. Test real supported client/Wine versions and games only on the intended host
   with a legitimate account. Detection, inspection, callback mutation, applied
   routing, relay traffic and stable gameplay remain separate evidence fields.

No Level 2 privileged networking, Wine executable, commercial client or gameplay
test was run by this subsystem audit. Current environment initially lacks LLVM
PE tools and Wine; native tests do not establish Windows ABI or live compatibility.
