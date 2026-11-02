# Discovery and tooling source audit

Baseline: `c0525a74c35fd74c815326d957c21a593a6aaccb`. This note records source inspection, not live game compatibility. Line references below describe that baseline.

## Inspected inventory and responsibilities

All 14 files in `tools/` were read, including their executable code (1,467 lines total):

| File | Purpose and dependencies | Implemented / incomplete |
| --- | --- | --- |
| `audit-source.py` | Git object and metadata privacy scanner; Python stdlib, Git | Scans tracked HEAD objects and reachable commit emails; deliberately not a comprehensive secret scanner, and does not inspect uncommitted source. |
| `check-exitlag-abi.sh` | Compare PE imports/exports and Wine missing-import guard names; LLVM tools, Bash, awk | Export-name coverage; does not prove struct/vtable/signature semantics or successful runtime callbacks. |
| `check-exitlag-version.sh` | Hash/version baseline of official local EXE; coreutils, strings | Detects binary drift; a user can record any binary, so recorded does not itself mean live verified. |
| `discover-game-processes.py` | Join kernel socket inode tables with `/proc/PID/fd`, inspect ancestry | IPv4/IPv6 TCP/UDP, own visible processes; advisory environment classification, no cross-netns discovery or immutable process snapshot. |
| `identity-map-assistant.py` | Show discoveries and append a human-confirmed identity map | Requires explicit Windows identity and one selected PID; no authoritative ExitLag catalogue resolution. |
| `scan-linux-games.py` | Inspect Steam roots/libraries/manifests and executable candidates | Emits commented-out candidates; guesses Windows path, no service catalogue verification, broad executable heuristics. |
| `exitlag-doctor.sh` | Read-only host/runtime/config diagnostics; shell/system commands | Actionable checks; some capability and ABI wording overstates what static inspection proves. |
| `exitlag-setup.sh` | Compatibility entry into shared installer; Python, manifest | Uses verified payload installer; inspect shared installer for its privilege guarantees. |
| `run-exitlag-production.sh` | Start official client and shim after drift/ABI checks; Wine, LLVM | Clears experiment overrides; assumes project-local Wine, can kill all processes in selected prefix. |
| `run-exitlag-gameprefix.sh` | Research launcher with callback surface and trace overrides | Explicit experimental environment, not production evidence; same prefix-wide lifecycle. |
| `install-nfextlag-stub.sh` | Register presence-only driver/service in Wine prefix | Refuses existing target; not transactional if `sc create` fails after file install. |
| `remove-nfextlag-stub.sh` | Stop/delete service and remove only exact built stub | Hash-gated driver deletion; service deletion precedes hash validation; depends on current stub build matching historical installation. |
| `install-wbemprox-prefix-override.sh` | Disabled deployment method with diagnostic | Returns failure intentionally; references unavailable research launcher. |
| `restore-wbemprox-prefix-override.sh` | Restore saved original prefix DLL | Requires explicit saved file; backup is one project path rather than per-prefix manifest. |

Also inspected backend process resolution (`backend/exitlag-netd.c:430–548,694–944`), `backend/identity-map.example`, and relevant discovery/assistant/identity/doctor/RPC regression scripts.

## Confirmed findings

### D1 — High: strict identity mode still accepts untrusted argv alone

Evidence: loader accepts any non-absolute source containing `.exe`/`.EXE` (`backend/exitlag-netd.c:754–759`), then `mapped_identity_for_pid()` compares every argv token against **all** configured sources (`:842–854`). Any native process can supply such a token, including the canonical absolute path of a configured native executable. `resolve_pid_path()` describes strict mode as preventing argv impersonation (`:880–882`), but the argv fallback defeats that protection. Existing `tests/test-identity-map.sh` tests an absolute native mapping and an unrelated exe-looking argument, not the configured source placed in an unrelated process's argv.

Impact: the socket still must be observed, but an unrelated socket owner can acquire a configured Windows identity. This violates narrow interception intent; it is not evidence of an authentication or subscription bypass. Recommendation: remove argv-only authorization from strict mode; require verified executable identity and an explicit supported Wine proof scheme. Add negative tests with a configured `.exe` source and native argv spoof.

### D2 — High: prefix environment is treated as authorization for every process

Evidence: `mapped_identity_for_wineprefix()` reads `WINEPREFIX` from arbitrary PID environment and returns its configured mapping (`backend/exitlag-netd.c:801–827`); no executable/provenance validation precedes this fallback (`:856`). `discover-game-processes.py:140–159` similarly classifies any ELF process as Wine/Proton based solely on environment and suggests a prefix source. Any process can set these variables; these are useful hints, not proof.

Impact: a native process with a mapped `WINEPREFIX` can receive that game's identity. A shared prefix also intentionally maps launchers and unrelated programs to the same identity. Recommendation: explicit executable-plus-prefix binding with trusted executable verification; fail closed when unable to establish identity. Preserve advisory hints separately. Test native environment spoof, valid configured loader, shared prefix, symlink, deleted executable, process exit, and PID reuse.

### D3 — Medium: discovery process ownership is a time-separated, namespace-local observation

Evidence: socket tables are read first (`discover-game-processes.py:43–63`), fd owners next (`:113–137`), metadata later (`:192–206`). No `/proc/PID/stat` start time or pidfd ties these together. It reads only `PROC/net/*`, the current network namespace; root visibility of `/proc` does not provide socket tables for other namespaces.

Impact: exit/PID reuse can produce incorrect advisory identity; containers and launchers with private namespaces may be missing. `/proc` permissions, `hidepid`, and Wine fd duplication can yield incomplete or multiple owners. Recommendation: process-generation snapshots and immutable executable metadata, explicit namespace/visibility reporting; never auto-enable based solely on this discovery output. Add synthetic `/proc` fixtures for inode sharing, vanished processes, PID reuse, and namespace mismatch.

### D4 — Medium: ABI checker verdict exceeds verified semantics

Evidence: `check-exitlag-abi.sh:30–39` parses symbol names, `:44–81` compares symbols, `:92–115` scans crash guards by function name alone, then `:132–134` prints “compatible” and suggests recording as known-good. Missing Wine PE directory is SKIPPED but overall exit may be zero (`:87–89`). Failure statuses in process substitutions do not reliably propagate into the parent shell; unreadable Wine exports can be interpreted as missing/guardable names.

Impact: a changed vtable, struct layout, behavior, or unexamined Wine module can pass import coverage. Recommendation: report “symbol coverage verified,” separate incomplete checks from incompatibility, preserve fail-closed start on unreadable required input, and require synthetic callback plus live regression before labeling builds verified. No source-derived check can prove full proprietary behavior.

### D5 — Medium: assistant hides discovery errors and allows ambiguous map writes

Evidence: `identity-map-assistant.py:24–33` converts subprocess failures and malformed JSON to an empty list, and `:93–98` returns success with a no-games message. Map write at `:155–165` does not validate tab/newline/NUL characters, detect an existing source with a different target, or lock the append. Concurrent writers may duplicate entries or conflict, causing backend startup failure. PID/source are not rechecked before append.

Recommendation: distinguish no candidates from failed discovery; validate one-line fields against backend format and reject conflicting mappings; use a lock and revalidate PID generation before writing. Add mock-based error/field/conflict tests.

### D6 — Low: Steam scanner is intentionally heuristic and has malformed-input gaps

Evidence: only first detected Steam root is used (`scan-linux-games.py:26–30`), VDF/ACF parsing is regex based (`:33–60`), `int(appid)` is unchecked, and a malformed manifest with missing name/installdir can reach `.lower()` on `None` (`:53`). Branch `elif win_exe and not bins` is unreachable after `if not bins` (`:182–185`). Existing compatdata directory is treated as Proton selection even for a subsequently switched native build (`:169–179`). Prefix and directory translation Windows candidates are guesses (`:132–140`).

Recommendation: robust bounded VDF parser, validate fields, distinguish installed candidates from currently observed runtime, inspect all unique Steam roots, preserve candidates as disabled until exact Windows identity confirmation. Test malformed/partial manifests, duplicate libraries, switched builds, special characters, and native binaries below heuristic size threshold.

### D7 — Low: launcher and legacy deployment lifecycle limitations

Evidence: production/research launchers call prefix-wide `wineserver -k` unless `KEEP_PREFIX` is set (`run-exitlag-production.sh:46–49`, `run-exitlag-gameprefix.sh:22–25`). Production version checker reads `EXITLAG_EXE` or repository default, unlike launcher/ABI checker `EXITLAG_APP_DIR` (`check-exitlag-version.sh:20`, `run-exitlag-production.sh:17–18`), so managed installation drift baselines may be ignored. Manifest/log names are timestamp-second based and can collide. Stub install can leave driver file when service registration fails; uninstall deletes service before validating that it owns the driver.

Recommendation: dedicated prefix, consistent state paths, per-session unique log directories, transactional ownership manifests and rollback; retain existing behavior until managed-launcher migration is tested.

### D8 — Low: discovery address parser is not defensive on malformed hex

Evidence: `bytes.fromhex()` is outside exception handling (`discover-game-processes.py:73`); out-of-range ports are accepted. Kernel proc tables are expected well formed, so this is parser robustness rather than a demonstrated remote security issue. Add positive IPv4/IPv6/mapped tests plus malformed/truncated input and port bounds.

### D9 — Medium: default assistant hides unconnected UDP socket owners

Evidence: `identity-map-assistant.py:84` defaults `--min-port` to 1024; discovery applies that threshold to the remote endpoint of every transport (`discover-game-processes.py:201–203`). An unconnected UDP socket (including normal dynamic `sendto()` users) is represented in `/proc/net/udp*` with a wildcard remote address and port zero. Such candidates are filtered out even when the actual game remote ports exceed 1024. This is a visibility gap rather than proof of a routing failure in the backend. Recommendation: preserve unknown UDP peers as explicitly unknown or provide an option and honest advisory explanation; do not invent remote peers. Add connected/unconnected IPv4 and IPv6 UDP discovery fixtures, with local versus remote port semantics stated.

## Performance and architecture

- Discovery scans all visible process fd directories on every run, allocating full fd lists; cost scales with process count and open fds. There is no measured benchmark, so no speedup claim is justified.
- Backend inode-to-PID logic also scans all `/proc` fd directories and ranks candidates using user-controlled comm/argv. Reusable generation-bound attribution would avoid duplicated, inconsistent security policy, but extracting it requires regression coverage first.
- Full filesystem scans for Steam binaries and prefix `.exe` candidates run synchronously. Results are candidates only, and caching/incremental scans must invalidate on file identity changes.
- Control-plane utilities should expose evidence quality and safe configuration; privileged backend must independently verify identities. UI detection must remain distinct from inspection, official redirect decision, applied NAT, verified relay traffic, and gameplay.

## Unverified hypotheses / required external validation

- Wine/Proton socket duplication behavior depends on runtime/version; baseline comments say both “game does not own socket” and code ranks Windows owners ahead of wineserver. Need actual observed owner evidence for each runtime rather than generalizing.
- Native executable ownership is vulnerable to mutable binaries under a mapped writable path; extent depends on intended same-UID trust model. Trusted map file and runtime UID do not make mutable argv/environment authoritative.
- No authoritative ExitLag catalogue interface is present. Why detection lacks redirect decisions requires exact identity, callback and service evidence from the official client; do not synthesize a decision.
- No live anti-cheat or game support established by these utilities. Steam manifests and a process socket are discovery evidence only.

## Safe first implementation candidates

1. Highest security value: close strict-mode argv/prefix spoofing with explicit backwards-compatible migration documentation and executable-bound prefix mappings. Requires backend owner coordination and regression tests; do not silently broaden interception to preserve apparent compatibility.
2. Small cloud-safe utility change: make discovery failure explicit and map field/conflict validation atomic, covered by stdlib `unittest` mocks.
3. Defensive address parsing and fixture-based `/proc` parser tests; no live service or kernel capability needed.

No functional code was changed during this audit.

Targeted cloud-safe checks during this subsystem audit: `python3 tests/test_discovery_filters.py` passed (3 tests). Directly passing malformed hexadecimal input to `fmt_addr()` reproduced D8 as an uncaught `ValueError`. Baseline suite evidence is recorded centrally by the root agent.

## Implementation and verification follow-up

Strict and no-map identity resolution no longer derives a Windows identity from
argv. Native keys bind the actual `/proc/PID/exe`. Prefix rows now require an
explicit third `OWNER_EXE` field as well as canonical `WINEPREFIX`; legacy
prefix-only rows fail startup with migration guidance. The assistant, scanner,
doctor and Linux installer/editor use the revised grammar. This is a same-user,
prefix-wide allowlist, not attestation of a specific Windows image; executing an
approved runtime with the approved prefix remains intentionally within that
allowlist. PID reuse, mutable executable paths and shared-socket ranking remain
separate attribution hardening work.

`python3 tests/test_identity_tools.py` passed 11 mock-only tests. Root executed
the expanded synthetic IPC identity test, including owner/prefix positives and
negatives and no-map argv spoofing. A fixture timing failure was investigated
rather than weakening expectations: immediately after `subprocess.Popen()` of a
copied `/usr/bin/sleep`, `/proc/PID/environ` was empty in **19 of 100** direct
observations in this cloud environment, despite the supplied `WINEPREFIX`.
The test now waits up to five seconds for the fixture's expected executable and
environment before asking the backend to resolve it. Root reported **50/50**
complete identity regression runs passing after this readiness barrier.

These figures measure fixture startup visibility, not network throughput or
game support. In production, an unreadable/not-yet-visible prefix prevents
translation and retains the genuine host executable (no prefix identity is
authorized); this can miss an initial routing opportunity. Retry/lifecycle
handling under real Wine/Proton process transitions remains unverified and
requires further targeted attribution tests and a suitable live host.
