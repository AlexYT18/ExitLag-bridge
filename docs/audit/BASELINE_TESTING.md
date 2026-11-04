# Baseline environment and test evidence

Source baseline: `c0525a74c35fd74c815326d957c21a593a6aaccb`. Results below are actual executions; final changed-tree results are recorded separately in [ITERATION_REPORT.md](ITERATION_REPORT.md). A suite count is a count of aggregate commands, not individual assertions or games.

## Environment observed

| Property | Observation |
| --- | --- |
| OS | Debian GNU/Linux 13.6 (trixie), x86_64; **not Arch Linux** |
| Kernel | Linux `6.18.57`, x86_64 |
| User | UID/GID 1000 (`agent`); no host sudo executable |
| Initial sandbox | Effective/permitted/bounding capabilities zero, `NoNewPrivs=1`, Seccomp mode 2. Loopback socket creation denied; user namespace UID-map write denied. |
| After user enabled full access | Effective/permitted capabilities still zero on host; bounding mask `000001ffffffffff`, `NoNewPrivs=0`, Seccomp 0. Root execution tool can create user/network namespaces. Subagents may still report their earlier restricted sandbox; root execution results decide final status. |
| Namespace probe | `unshare --user --map-root-user --net` succeeded; loopback configured, temporary `inet exl_cap_probe` nftables table added/listed/deleted only inside that namespace. A queue/bypass rule could also be installed there. This probe alone is not a full NFQUEUE integration pass. |
| Preinstalled build tools | GCC/G++ 14.2.0, GNU Make 4.4.1, Python 3.12.14; libmnl runtime 1.0.5, iproute2, unshare, capsh |
| Initially absent | LLVM command-line tools, libmnl development header/link, nft executable, ShellCheck, cppcheck, Wine, official ExitLag, real games |
| Locally prepared tools | Debian signed-repository packages: LLVM/Clang/LLD 19.1.7, libmnl-dev 1.0.5, nftables 1.1.3, ShellCheck 0.10.0, cppcheck 2.17.1; extracted outside repository under a local prefix, without system installation |
| Network configuration | Supported environment status: enforced unrestricted HTTP policy, no configured credentials or outbound identities. Commands preserve proxy/CA configuration. No account data was requested. |

The environment changed during the task. Initial permission-denied results are retained; they are not code regressions and are not silently relabeled as passes. Namespace support was probed again after access changed. No restrictions were bypassed.

## Clean-baseline aggregate runs

The initial checkout was tested before functional edits:

```sh
tests/run-all.sh all
```

**1 PASS / 8 FAIL / 7 SKIP.** Setup simulation passed. Missing LLVM and libmnl headers caused build failures and dependent test failures; default sandbox denied sockets for discovery fixtures. Two official-client checks and five root/live checks skipped with reasons. The original runner did not preflight all dependencies.

A separate pristine baseline was extracted with:

```sh
mkdir -p /tmp/exitlag-baseline
git archive c0525a74c35fd74c815326d957c21a593a6aaccb | tar -x -C /tmp/exitlag-baseline
# Prepare normal build dependencies, then in that directory:
tests/run-all.sh all
```

With dependencies and local sockets available: **5 PASS / 4 FAIL / 7 SKIP**.

| Command group | Result | Evidence/reason |
| --- | --- | --- |
| helper build | PASS | GCC/libmnl linked baseline daemon |
| identity map positive/negative | PASS | Existing test only; audit found its negative did not cover source-path spoof |
| doctor diagnoses | PASS | Existing synthetic diagnostic assertions |
| RPC surface | PASS | Existing no-queue scope assertions |
| setup simulation | PASS | 13 shared-installer unit tests |
| shim build | FAIL | LLVM CL driver interpreted absolute `/workspace/...` input as an option: `no input files` |
| crash-guard build | FAIL | Same absolute-path issue; this test only builds, not executes a Windows runtime |
| process discovery | FAIL | Copied standalone Python lost standard-library prefix (`/install`, no `encodings`) |
| identity assistant | FAIL | Same broken copied-interpreter fixture |
| ABI against official client, healthy-client doctor | SKIP | Proprietary client absent |
| four system groups, one live group | SKIP | Baseline invoked as UID1000; root requirement not met |

The two discovery fixtures were then re-executed on the **unchanged baseline** with `PYTHONHOME` set to the real Python `sys.prefix`: discovery **8 assertions PASS**, assistant **10 assertions PASS**. This identifies a fixture portability defect rather than demonstrating a discovery implementation improvement.

## Additional baseline checks

- Explicit account-free Python suites: discovery filters 3, installer 13, Linux supervisor 5, Mac distribution 4, source-audit 4: **29 tests PASS**.
- Shell syntax for 17 assigned harnesses and AST parsing for 10 assigned Python test sources passed during subsystem review. The final cloud runner expands syntax coverage to the current source tree.
- Broad `unittest discover -s tests` was unsuitable: two packaging/display-dependent scripts consume import-time argv, producing **2 import errors** alongside the 29 unit passes. The new runner must select explicit suites; syntax success never substitutes for executed assertions.
- Initial macOS discovery: 33 tests, 13 passed, 19 errored, 1 skipped in the restricted sandbox. Eighteen errors were socket permission failures; one was missing macOS `pfctl`. Platform parser availability must be an explicit skip. Changed-tree rerun is reported separately.
- The baseline shim endpoint function was mechanically reproduced in a native sanitizer harness. It accepted non-loopback, malformed and overflowed addresses. See [SHIM.md](notes/SHIM.md). ASan/UBSan execution succeeded with leak detection disabled; LeakSanitizer failed under the subagent ptrace sandbox and is **not** a leak-check pass.

## Reproduction on Arch Linux

On a disposable Linux development host, install normal distribution dependencies rather than the cloud's temporary prefix:

```sh
# Arch Linux (inside an Arch development environment)
sudo pacman -S --needed base-devel clang lld llvm libmnl nftables iproute2 python shellcheck cppcheck
```

Run L1 as a normal user and L2 only through the disposable namespace wrapper:

```sh
tests/run-cloud.sh --sanitizers
tests/run-isolated.sh
```

Check the JSON/log summaries and reasons for every SKIP. Some hosts disable unprivileged user namespaces or lack NFQUEUE kernel support; the wrapper must report unavailable prerequisites, never run shared-host firewall tests as a fallback. The new workflow targets Arch only, per the user's later scope clarification. Local Arch container results are recorded in ITERATION_REPORT.md; Debian evidence alone is not an Arch result. No GitHub-hosted workflow execution is claimed.

L3 requires a separate suitable host with the original client, legitimate account/subscription and selected game. Record the pipeline stages independently in [compatibility.md](../compatibility.md); no Cloud result proves gameplay or anti-cheat compatibility.
