# Tests and CI source audit

Baseline: `c0525a74c35fd74c815326d957c21a593a6aaccb`. All tracked files under `tests/` and `.github/` were read, including C/C++ probes, import definitions and issue/PR templates. Findings below concern the baseline before functional changes.

## Inventory and purpose

| Files | Purpose and dependencies | Capability / principal gap |
| --- | --- | --- |
| `tests/run-all.sh` | Bash cumulative unit/system/live runner | Aggregates logs and failure status; dependency/skip handling is incomplete, accepts unknown tiers as successful zero-test runs. |
| `tests/test-identity-map.sh` | Native helper, Bash, Python, `/proc`, loopback | Exact-executable positive and argv-spoof negative, authenticated v3 handshake; no PID reuse scenario. |
| `tests/rpc-surface-test.sh` | Native helper, Python, loopback | Unreported-PID rejection and malformed authenticated requests; redirect policy is checked with text grep, not exercised. |
| `tests/ipc-security-test.sh` | Root, sudo/run-as-nobody, helper, Python | UID/token/version/lifecycle negatives; malformed tests mostly assert survival rather than rejection semantics. |
| `tests/ipc-fuzz-test.sh` | Root, helper, Python, nft | Deterministic hostile corpus, alternate sanitizer binary supported; not coverage-guided fuzzing, does not enforce sanitizer diagnostics, and cleanup unexpectedly invokes nft teardown despite `--no-queue`. |
| `tests/harden-runtime-test.sh` | Root, nft/NFQUEUE, Python, external server; one scenario needs Wine/LLVM | Nine lifecycle/fail-open scenarios; global process cleanup and host networking assumptions make direct host execution unsafe. |
| `tests/ipv6-redirect-test.sh` | Root, nft/NFQUEUE, IPv6 route, Python | Mock v3 callback, original-peer/bidirectional TCP and invalid redirects; requires external IPv6 route and reports missing support via exit 0. |
| `tests/test-tcp-redirect.py` | Root, nft/NFQUEUE, Python | Intended loopback TCP mock with reverse NAT assertions; stale unauthenticated protocol v2 makes it unusable with current helper. |
| `tests/test-udp-observe.py` | Root, nft/NFQUEUE, veth/netns, Python | Intended lifecycle, post, remote-rule, flow-control, active/observe data proof; stale unauthenticated protocol v2, only one endpoint and datagram. |
| `tests/test-shim-reconnect.sh`, `tests/nfapi-reconnect-smoketest.cpp` | LLVM PE tools, patched Wine runtime and prefix, native helper | Silent helper timeout/retry plus valid v3 reconnect; depends on hard-coded project runtime paths. |
| `tests/build-nfapi-compat-smoketest.sh`, `tests/nfapi-compat-smoketest.cpp` | LLVM PE tools, shim | Builds missing-import guard executable; runner only builds it and never runs its return-value assertions under Wine. |
| `tests/verify-nfapi-abi.sh` | LLVM, vendor client, built shim | Duplicate export comparison with incorrect shim path; does not detect empty required-export list. |
| `tests/discovery-test.sh`, `tests/test_discovery_filters.py` | Python, Bash, `/proc`, loopback, interpreter copies | Socket-owning child vs launcher, source path, exact port filters, argv heuristic exclusion; read-only nft check treats permission/tool errors as equal empty snapshots. |
| `tests/identity-assistant-test.sh` | Above plus helper | Explicit Windows identity confirmation, idempotence, helper map acceptance; fixed helper port, last child is killed but not waited. |
| `tests/doctor-test.sh` | Bash/Python, diagnostic tool, optional nft/sudo | Distinct diagnosis, capability caveat, exit codes; read-only nft check can succeed without nft access. |
| `tests/setup-simulation-test.sh`, `tests/test_installer.py` | Python | 13 meaningful account-free installer lifecycle/integrity/path/ownership checks, simulated Wine/vendor handoff. |
| `tests/test_linux_desktop.py` | Python, Linux `/proc` | Five account-free map/lease/parent/installed-supervisor boundary checks; no actual UI or kernel routing. |
| `tests/test_mac_distribution.py` | Python | Four signature/notary/link-boundary checks using fake payloads and mocked Apple tools. |
| `tests/test_source_audit.py` | Python, Git | Four privacy regression checks with fixture commits; fixture commits are local temporary test objects. |
| `tests/test_desktop_ui.py` | Installed tree argument, Tk/X display | Actual UI first-run invalid installer rejection; executes at import time. |
| `tests/test_installed_routing.py` | Installed tree argument, non-root test UID with sudo, disposable network namespace | Actual UID-scoped rules and lease/parent cleanup; executes at import, no payload redirection assertion. |
| `tests/installer_fresh_runtime.py` | Payload directory, pinned Wine/runtime dependencies, X display | Actual WMI bootstrap/idempotence/remove/purge, no proprietary client. |
| `tests/portable-arch-container.sh` | Disposable privileged Arch container, pacman/network, pinned portable archive | Install/UI/Wine/WMI/rules cleanup/removal; mutable Arch base and full `--privileged` instead of minimal capabilities. |
| `tests/test-external-route.sh` | Root, real running ExitLag profile, reachable external server | Native exact-map vs negative callback/DNAT proof; not verified gameplay or relay capture. |
| `tests/validate-external-prefix.sh` | Root, real ExitLag, patched Wine, external Windows probe, external server | Mapped vs unmapped external prefix routing proof; global `pkill`, fixed prefix directories and potentially destructive overwrite. |
| `tests/external-probe/external-tcp-probe.c`, `kernel32.def`, `ws2_32.def` | PE compiler/linker and Wine | Small Windows TCP connect/I/O probe; Win64 SOCKET represented as 32-bit int, unbounded blocking recv, simplistic CLI parsing. |
| `tests/fakegame/sleeper.c` | Windows compiler/Wine | Process detection fixture only; has no sockets or traffic and proves no routing. |
| `.github/workflows/installer-validation.yml` | Ubuntu 22.04/24.04 hosted runners, network, sudo, pinned action SHAs | Build/package/runtime/account-free tests and namespaced lifecycle; no sanitizer/static-analysis/source Arch job. |
| `.github/workflows/linux-portable-compatibility.yml` | Manual Ubuntu/Arch release-artifact jobs | SHA-pinned released archive; Arch does not build/test current source, uses privileged container. |
| `.github/workflows/ubuntu-package-compatibility.yml` | Manual release-package jobs | Checks pinned release SHA + ref; not current-source regression coverage. |
| `.github/workflows/source-privacy.yml` | Python/Git, pinned checkout | Source/privacy scan and fixture regressions. |
| `.github/ISSUE_TEMPLATE/game-compatibility.yml`, `.github/pull_request_template.md` | GitHub forms/Markdown | Requests reproducible scope/privacy; stages are prose, not explicit DETECTED/INSPECTED/REDIRECT/RELAY/GAMEPLAY fields. |

## Confirmed findings

### TEST-01 — High: destructive test isolation is optional

Evidence: `tests/harden-runtime-test.sh:34-36` uses global `pkill -x exitlag-netd`/SIGKILL, `:41` invokes nft teardown and `:303` begins by tearing everything down; `:17` and `:62-68` connect to a public game-server endpoint. It neither enters nor verifies a dedicated process/network namespace. `tests/run-all.sh:78` invokes it directly when EUID is zero. `tests/validate-external-prefix.sh:49-51` also uses a global kill/teardown and fixed prefix directories (`:27-28`, `:58`). A contributor following the sudo instructions can kill an independent project session or modify host network state. Recommendation: disposable network+PID namespaces, owned PID handles and unique runtime paths, fully local peers; gate system tier on isolation and capabilities. Do not execute these host-wide scenarios in Cloud.

### TEST-02 — High: stale primary TCP/UDP integration protocols

Evidence: TCP `tests/test-tcp-redirect.py:24,128` and UDP `tests/test-udp-observe.py:22,192` send version 2 and a 16-byte HELLO; current `backend/protocol.h:27` is v3, and helper requires the full token-bearing hello before matching version. They cannot pass authentication against this source. Neither is included in the system runner (`tests/run-all.sh:75-79`) or workflows. Recommendation: shared mock protocol client deriving version from header, explicit private token paths, real authenticated mock integration, add isolated execution to CI. These tests were not executed here (no CAP_NET_ADMIN).

### TEST-03 — Medium: SKIP can be recorded as PASS

Evidence: `tests/ipv6-redirect-test.sh:39-40` exits zero if IPv6 loopback/route is missing; `tests/run-all.sh:44-49` records every zero exit as PASS. The root check tests EUID rather than CAP_NET_ADMIN. The runner also accepts any tier string and can end with zero checks and exit zero (`:57-86,109`). Recommendation: explicit skip exit 77, runner status handling and validated tier arguments, regression test subprocess fixtures.

### TEST-04 — Medium: important unit checks absent from main runner and CI

`tests/run-all.sh:60-70` does not directly include Linux supervisor, macOS distribution or source-audit Python tests (some are run elsewhere in workflows), nor import-safe Python discovery. Five account-free Python suites were executed separately here and passed 29 total test methods. `python3 -m unittest discover -s tests -p 'test_*.py' -v` fails two imports because installed UI/routing scripts access argv at module top level (`tests/test_desktop_ui.py:10`, `tests/test_installed_routing.py:14`). Recommendation: one cloud-safe entry point with explicit prerequisites, import-safe integration main functions and consistent status reporting.

### TEST-05 — Medium: survival is weaker than authorization/redirect validation

`tests/ipc-fuzz-test.sh:41-59` broadly catches send/receive/auth failures and only checks the helper is alive; `tests/rpc-surface-test.sh:77-87` greps source strings for redirect policy. Address replies target uncreated request tag 1, so invalid destination semantics may never be reached. `tests/ipc-security-test.sh:56` accepts any >=12 received bytes as a successful HELLO. Recommendation: parse exact ACK, assert request/rejection outcomes on actual pending callback flows, assert sanitizer reports are absent and processes exit cleanly, deterministic fragmentation/truncation corpus plus suitable native fuzz targets. Existing tests remain useful smoke/survival checks, not full semantic proof.

### TEST-06 — Medium: no source-based Arch/sanitizer/static-analysis CI

The only Arch job is manually triggered (`.github/workflows/linux-portable-compatibility.yml:3,59-79`) and tests a prebuilt release. Current-source CI is Ubuntu-only; no workflow runs ASan/UBSan, cppcheck/clang analysis or shellcheck. Actions are already SHA-pinned and contents permission read-only (positive). Recommendation: lightweight account-free source matrix for Arch + Ubuntu, native sanitizer corpus, ShellCheck and explicit PASS/FAIL/SKIP summaries. Keep privileged integration in constrained namespaces/containers, separate from source checks.

### TEST-07 — Low: ABI check duplicate path regression

`tests/verify-nfapi-abi.sh:9` points to `tests/build/nfapi.dll`, but source builds to `shim/nfapi/build/nfapi.dll`; `:13` suggests non-existent `tests/build.sh`. This test is not used by main runner (which calls `tools/check-exitlag-abi.sh`). Recommendation: consolidate into the canonical checker and reject an empty nfapi import requirement set.

### TEST-08 — Low: build-only smoke falsely suggests executed crash guard

`tests/run-all.sh:64` labels `tests/build-nfapi-compat-smoketest.sh` as a crash-guard smoketest. That script only builds/copies the executable. Runtime assertions in C++ lines 40-44 are never executed by this runner. Recommendation: label build-only, add separate Wine execution with dependency skip and preserve runtime vs compile evidence distinction.

### TEST-09 — Low: no-queue fuzz cleanup touches firewall

`tests/ipc-fuzz-test.sh:21` invokes nft teardown even though it explicitly runs `--no-queue` (`:27`) and claims never to touch netfilter. Remove that teardown; assert lack of ownership without deleting independent state. The no-state query also treats command errors/permission errors as absence (`:130-131`).

## Coverage gaps and unverified hypotheses

- No automated TCP flow state/timeout/cleanup unit suite, packet parser malformed corpus, UDP multi-endpoint/dynamic-remote/IPv6 reinjection, packet-loss/backpressure bounds or reproducible throughput/jitter/memory benchmark.
- PID reuse/exit races, arbitrary socket ownership changes, queue overload/disconnect during pending callback, conntrack cleanup collisions, NetworkManager/systemd-resolved/VPN coexistence need targeted tests. Source risks are reported by other subsystem audits; no live/kernel behavior was inferred here.
- Installed lifecycle checks exercise table scope/cleanup, not application traffic isolation or actual DNAT payload semantics.
- A mock callback proves kernel mechanics only. No game, relay or subscription behavior was tested.

## Executed baseline checks in this audit

Environment: Debian 13 x86_64, unprivileged UID 1000; no native builds or privileged network operations performed by this audit task.

| Command | Result |
| --- | --- |
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | FAIL: 31 cases, 29 passed, 2 import errors (installed UI/routing scripts consume `discover` as a path). |
| `python3 tests/test_discovery_filters.py` | PASS: 3 tests. |
| `python3 tests/test_installer.py` | PASS: 13 tests; tar extraction DeprecationWarning under Python 3.12, no failure. |
| `python3 tests/test_linux_desktop.py` | PASS: 5 tests. |
| `python3 tests/test_mac_distribution.py` | PASS: 4 tests. |
| `python3 tests/test_source_audit.py` | PASS: 4 tests. |
| `bash -n` for every `tests/**/*.sh` | PASS: 17 scripts. |
| `ast.parse` for every `tests/**/*.py` | PASS: 10 Python files. |

These repeated runs overlap the same 29 successful methods and must not be added together as distinct coverage. Privileged and Wine/client runtime cases were not run by this audit task; the parent task records the wider baseline and environment blockers.

## Smallest useful implementation candidates

1. Fix runner result semantics (validated tier, skip=77, report dependencies) and add account-free regression fixtures. This is independently testable without privileged operations and prevents misleading status.
2. Remove firewall teardown from no-queue fuzz harness and add an unprivileged deterministic authenticated IPC corpus, reused by sanitizer builds.
3. Modernize mock TCP/UDP v3 authentication, then isolated local integration environments; cannot declare Level 2 pass without execution.
4. Add source-only Arch/Ubuntu CI plus sanitizer/static checks without bringing commercial binaries or accounts into CI.
