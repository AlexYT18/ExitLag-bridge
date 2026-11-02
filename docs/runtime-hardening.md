# Runtime hardening and evidence limits

This page describes the Linux runner lifecycle and earlier development reports.
It does not certify a current live game session. See the
[initial audit](audit/INITIAL_AUDIT.md), [test matrix](test-matrix.md) and
[roadmap](audit/ROADMAP.md) for current evidence and remaining validation.

## Harness scenarios

`tests/harden-runtime-test.sh` needs root and uses a native probe rather than a
game. The earlier report recorded ten passing scenarios; that number is a
historical result, not a rerun against the current source. Record a fresh run's
commit, environment, command and full PASS/FAIL/SKIP summary before using it as
release evidence.

| Scenario | Scope of the check |
|---|---|
| repeated start/stop cycles | helper/table creation and cleanup across repeated runs |
| stale nftables detection | refusal to overwrite an existing table without expected ownership |
| no helper bound to the queue | new probe traffic can use `queue ... bypass` |
| helper SIGKILL | response to abrupt helper loss in the probe scenario |
| runner SIGKILL | orphan helper/table recovery on the next authorized start |
| runner SIGTERM | cleanup through the runner's TERM/EXIT traps |
| runner SIGINT | cleanup through the runner's INT/EXIT traps |
| shim reconnect | timeout/reconnect against the harness's controlled peer |
| protocol mismatch | rejection of an incompatible peer |
| unreachable destination | helper liveness after attempting an unreachable test endpoint |

The unreachable-destination scenario uses TEST-NET-3 (`203.0.113.1`). It does
not test physical link down/up, DNS changes, sleep, reboot or recovery of an
already established relay session.

SIGKILL cannot run a trap. Its recovery scenario must be kept separate from
TERM/INT cleanup. Likewise, a fresh direct connection succeeding after helper
loss does not show that an established DNAT connection migrated off the proxy.
Conntrack retains established translations, and queue bypass does not cover
queue saturation or a still-bound but stalled listener.

## Runtime ownership

`backend/runtime-guard.sh` is sourced by the active developer runners:

- `flock` on `/run/exitlag-linux/backend.lock` prevents a second cooperating
  runner from starting.
- The pidfile records the helper PID and resolved executable path. Recovery
  compares those with the live process before signalling it; an unrelated
  reused PID is left alone.
- On the next start, recorded orphan state can be recovered. A table without
  verifiable project ownership causes refusal rather than automatic deletion.
- Long-lived children close the runner's lock descriptor so they do not keep
  that lock after the runner is killed.
- `runtime_guard_wait` waits for the helper or an optional timer. Helper exit
  returns control to the runner's cleanup trap instead of waiting out the timer.

The dedicated `inet exitlag` table bounds the project's firewall surface.
Deleting it does not remove existing conntrack translations. Packaged routing
has its own supervisor and user-scoped authorization; see the
[installer guide](../installers/README.md).

## Heartbeat and historical restart reports

The helper's nominal heartbeat interval is 2 seconds; the shim sets 5-second
socket timeouts and retries lost connections. These mechanisms are intended to
recover a peer connection that Wine otherwise leaves apparently established.
Timeout values are not a guarantee of end-to-end game recovery.

Earlier development notes reported ExitLag/Wine restarts followed by shim
reconnect, WoW restarts followed by new TCP redirects, and Battle.net traffic
remaining unproxied. Those observations predate this audit and include protocol
2 examples; the current protocol constant is 3. Private live traces and account
state are not in this checkout. They must not be read as results for the current
installed package or as proof that every state item is cleared on reconnect.

## Production export policy

Earlier development found a bridge defect: supported exports returned failure
unless listed in `EXITLAG_NFAPI_SUCCEED`. Omitting UDP entries therefore stopped
active UDP behavior even when the callback shape matched the expected contract.
That history is one reason a missing redirect cannot automatically be blamed
on the official client.

The shim now has a built-in supported-export table and a default extensions
version (`EXITLAG_SUPPORTED_EXTENSIONS_VERSION`).
`EXITLAG_NFAPI_SUCCEED` and `EXITLAG_NFAPI_EXTVER` remain research overrides.
`tools/run-exitlag-production.sh` clears these and synthetic injection/tracing
variables. Normal policy logs identify the selected policy source. Neither a
success return from a compatibility export nor a policy log proves that the
corresponding game traffic was relayed.

## ExitLag updates

`tools/check-exitlag-version.sh` compares product version, SHA-256, size and
missing-import guard counts with a locally recorded known-good build. Its exit
codes are 0 unchanged, 1 drift and 2 no baseline. The default baseline lives at
`runtime/exitlag-build-baseline.txt`; it is local runtime state, not a supplied
known-good client in this source snapshot.

`tools/run-exitlag-production.sh` responds to an unknown build by running
`tools/check-exitlag-abi.sh`. A successful static check permits launch with a
warning; a failed check refuses launch. The check covers imported nfapi symbols
and missing Wine imports covered by guards. It cannot establish unchanged
callback semantics, login, relay behavior or GUI compatibility. See
[ExitLag updates](exitlag-updates.md).

## Stopping a developer runner

The current TCP/UDP runners install INT/TERM/EXIT traps and use
`runtime_guard_wait`. Use Ctrl-C for a foreground runner, or send TERM to the
specific runner PID when managing a background run. Check cleanup output and
owned helper/table state afterward. Do not use a broad `pkill -f` pattern that
can match the issuing shell or unrelated sessions. SIGKILL is an emergency
termination requiring later ownership-checked recovery; it is not ordinary
cleanup.

Older notes about killing a foreground `sleep` child describe a previous wait
implementation and are not current stop instructions.

## Logging and privacy

Helper and shim logs use an 8 MB rotation threshold with one previous file.
The helper checks size periodically (every 256 lines), so files can exceed the
threshold between checks. Per-file rotation does not cap the total of session
directories, Wine/vendor output, prefixes or other diagnostic artifacts.

Normal helper logs contain endpoints, PIDs, executable paths, routing decisions,
errors and cleanup. Default UDP diagnostics are metadata-only: payload prefixes
and hashes are not recorded. Helper log files are private (0600), single-link
regular files opened without following path-component symlinks; rotation keeps
an anchored directory descriptor. The session token is excluded from logs.
Endpoints and executable paths still require privacy review. Research tracing exposes
more call details. Redact paths, addresses, packet content and account data
before sharing diagnostics; do not upload an entire prefix or raw capture.

## Validation still open

No completed physical link down/up test, reboot/sleep recovery test or
long-duration soak beyond the historical roughly 25-minute session is recorded
here. Existing queue, transport and lifecycle tests have narrower scopes.
The [roadmap](audit/ROADMAP.md) defines work to perform; its scenarios are not
claims of completed validation.
