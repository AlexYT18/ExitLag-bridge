# Testing

`tests/run-all.sh` is the Linux regression entry point. Tiers are cumulative:

```sh
tests/run-all.sh unit          # local build/logic checks, plus installed-client checks when available
tests/run-isolated.sh          # system tier in disposable network/PID/mount namespaces
sudo tests/run-all.sh live     # running-client tier; isolated cases still require namespace proof
sudo tests/run-all.sh all      # all registered tiers whose prerequisites are met
```

The source runner and its output define the registered tests and result counts.
Older totals in development notes describe earlier runs, not the current
checkout. See the [initial audit](audit/INITIAL_AUDIT.md) and
[test matrix](test-matrix.md); the [roadmap](audit/ROADMAP.md) lists work still to
validate. A planned check is not a passing result.

The runner skips installed-client checks when the proprietary files are absent,
and skips root/running-client scenarios when their declared requirements are
not met. These skips have reasons and are not passes. Unit tests still need
their build/runtime dependencies; an unavailable compiler or Wine can cause a
failure rather than an automatic skip. Do not infer that all unmet prerequisites
are detected by the tier gate.

## Unit tier

Most unit-tier checks run without root or an ExitLag account. Two legacy checks
inspect the installed official client and skip if it is absent.

| Check | Scope |
|---|---|
| shim/helper builds | compilation/linking with the selected toolchain |
| nfapi ABI | imports of the installed client versus shim exports and Wine guard coverage |
| identity map | exact mapping and rejection of unsupported/spoofed identities |
| crash-guard smoketest | selected synthetic imports return unsupported under Wine rather than crashing |
| doctor self-check | diagnostics for the configured installed environment |
| doctor diagnoses | diagnosis of deliberately broken test environments |
| RPC surface | selected PID/malformed-request behavior and policy/source assertions |
| discovery | network-owning process discovery against its fixtures |
| identity assistant | mapping proposal, confirmed Windows identity and file-loading behavior |
| setup simulation | install/status/removal/recovery against disposable state |

`tests/test-integration-support.py` separately checks the synthetic peers'
framing, v3 handshake validation, heartbeat and import/isolation gates using
socketpairs and temporary token fixtures. It does not run netfilter.

These checks do not establish gameplay or full vendor ABI semantics. In
particular, source assertions about a validator are weaker than a real packet
traversing that validator.

## System tier

| Check | Scope |
|---|---|
| IPC security negatives | uid/token authentication, malformed handshakes and token lifecycle |
| IPC hostile input | the suite's malformed authenticated messages and subsequent liveness |
| lifecycle hardening | start/stop, owned orphan recovery, traps, reconnect and probe fail-open cases |
| IPv6 active rewrite | real netfilter/IPv6 connection with a synthetic authenticated routing peer |
| IPv4 TCP redirect | v3 synthetic peer, real NFQUEUE/DNAT, loopback proxy, bidirectional payload and original application peer |
| IPv4 UDP observation/steering | one local veth endpoint, v3 synthetic peer, lifecycle/post messages and the existing single-datagram active contract |

Root alone is insufficient: netfilter capabilities, kernel features, tools and
IPv6 availability also matter. Record internal skips and unsupported-host
messages as limitations, even if an individual script returns success. A queue
bypass probe does not show survival of an existing proxied game connection.

The network integration harnesses require `tests/run-isolated.sh` to establish
different network and PID namespaces before mutation. The wrapper uses local
synthetic peers, not Internet game servers. If namespace creation or capabilities
are unavailable, report that limitation rather than running these scenarios in
the host network namespace.

## Live tier and manual tests

The registered live test checks an external Wine-prefix probe with a running
ExitLag, including an unmapped control. It needs the contributor's official
client/account setup and root privileges. It does not replace real gameplay.

WoW gameplay, title-specific UDP behavior and Proton/Steam launch behavior are
manual evidence. Earlier observations are summarized in
[compatibility](compatibility.md) and [routing stages](pipeline-stages.md).
This audit has not created new account-dependent game results.

Additional installer/Mac suites are documented in the
[installer guide](../installers/README.md) and [Mac README](../macos/README.md).
They are not all registered by the Linux regression runner.

## Recording a run

Keep the source commit, artifact hash where relevant, OS/kernel, architecture,
tool versions, command, exit code and PASS/FAIL/SKIP summary. Explain missing
client/account, unavailable capabilities, synthetic peers and manual steps not
performed. Use a dated run record instead of editing an old release snapshot
into an apparent current pass.

Under sudo, the runner attempts to execute ordinary unit commands as the invoking
user to avoid root-owned build products. Review local ownership before another
plain build if a suite was run directly as root. Per-test logs are written to
`runtime/logs/suite-<stamp>/`; redact private paths, addresses, packet content and
account information before sharing them.
