# Linux engineering roadmap and acceptance criteria

Baseline audit: [INITIAL_AUDIT.md](INITIAL_AUDIT.md). This roadmap is a work queue, not a list of implemented features. Track completed evidence in [ITERATION_REPORT.md](ITERATION_REPORT.md).

Current requested development target: **Arch Linux x86_64 only**. Other platform
code is preserved from upstream; it is outside this iteration's support scope.

## Validation levels

- **L1:** no account/game or networking privileges. Source builds, pure unit tests, loopback mock IPC, malformed inputs, static analysis and supported sanitizers. A sandbox denying socket creation must report that specific blockage.
- **L2:** disposable user/network/PID/mount namespaces with demonstrated NFQUEUE/nftables capabilities. Local synthetic endpoints and explicitly synthetic callback provider. Never mutate the shared host firewall or treat a marker variable alone as isolation proof.
- **L3:** original client, legitimate subscription and real supported Linux/Proton/Wine game on a suitable host. Record actual relay bytes and stable gameplay independently. No account secret needs to be shared with developers.

## P0 — Make the current narrow scope trustworthy

1. **Bound IPC transactions (B01–03).** Extract a small transport module. Acceptance: dribble, send backpressure, endless nested/stale frames, malformed headers, bad token/version and unauthenticated candidate cannot indefinitely block or displace an authenticated session; valid callbacks unchanged. L1 unit + real daemon no-queue tests; L2 delayed-shim packet tests. Synchronous callbacks still impose bounded latency, which must be measured.
2. **Stop identity spoofing (B04/D1/D2).** Native mappings use actual executable; prefix mappings bind to an explicit executable and prefix. Acceptance: canonical-source argv, argv0, unapproved-executable WINEPREFIX, exited PID and legacy ambiguous rows fail closed, exact configured native and executable-bound-prefix positives work. Document same-UID configuration trust and lack of independent Windows image proof. L1. Later PID generation and full tuple work remains separate.
3. **Validate shim IPC (SHIM-02/03/04/06).** Share wire records/constants, strict loopback endpoint and path/frame bounds. Acceptance: cross-PE build, unchanged exports versus baseline, native malformed/boundary tests and ASan/UBSan. L1. Runtime ABI compatibility remains L3.
4. **Honest, safe test execution (TESTS-01..04).** PASS/FAIL/SKIP JSON, no empty-success unknown tiers, v3 token fixtures, disposable privileged wrapper and local servers. Acceptance: regression tests distinguish all outcomes, no-queue tests do not touch nft, Arch source workflow builds current sources. L1; L2 execution recorded separately. CI configuration is not a completed CI run.
5. **Private diagnostics and privilege boundaries.** Stop default packet-content logging; secure root-facing files and finite leases; complete active session cleanup. Acceptance: no payload/token in default logs, symlink/FIFO/permission negatives, deliberate helper crash/restart cleanup inside L2. Root-checkout execution still requires trusted code ownership.

## P1 — Correct ownership and state before broadening traffic

6. **Full TCP socket attribution.** Match family, namespace, local/remote tuple, inode, UID and process start time; reject multiple candidates. Native/Proton/Wine ownership fixtures, multiple concurrent remote peers, source-port reuse, child launchers, process exit/PID reuse. L1 proc-fixtures + L2 sockets; L3 confirms real callback identity.
7. **Shim worker lifecycle.** Explicit stopped/starting/running/stopping states, retained thread handles, wake/cancel/join, deterministic `nf_free`, safe re-init and disconnect. Test synchronous/asynchronous mock callbacks and Wine stress; do not hold a lock across client callbacks. L1 portable state tests plus actual Wine runtime (L3 or separate account-free Wine host).
8. **UDP generation-safe registry.** Key endpoints by verified socket and process generation; bound memory and queues, expire state, reset/replay lifecycle on reconnect, reject stale posts, handle local-port rebind. Acceptance: reliable multi-endpoint/dynamic-remote tests, cleanup and loss/backpressure negatives. Keep active single-endpoint guard until all relevant L2 cases pass.
9. **Packet parsing/reinjection.** Pure bounds-checked IPv4/IPv6 parser, explicit fragment/extension policy, checksums, no truncated active reinjection. Fuzz + sanitizers cover lengths, extension chains, odd/maximum datagrams. IPv6 active UDP remains disabled until bidirectional L2 evidence.
10. **FirewallManager / SessionLifecycle.** Typed configuration; session-owned nft table/sets; acknowledged NFQUEUE configuration; UID/socket-scoped interception; one launcher guard; trusted watchdog recovery. Test stale/foreign tables, partial install, SIGTERM/SIGKILL, repeated start/stop, network interruption, original destination/reverse NAT. Residual established conntrack needs explicit policy.

## P2 — Measured compatibility and performance

11. **Discovery evidence.** Robust Steam manifests/library paths, explicit Proton/Wine prefix plus socket owner evidence, unconnected UDP visibility, exact executable mappings and clear human configuration when identity cannot be proven. Never invent a recognized Windows filename or infer routing from discovery.
12. **Performance baseline.** Versioned local workload: throughput, added latency p50/p95/p99, jitter, loss, CPU/RSS, concurrent flows, NFQUEUE saturation and startup/teardown. Compare identical kernel, build, payload sizes and scope. No speedup claim from a parser test or synthetic callback success.
13. **Coexistence.** Isolated fixtures and local-host validation for NetworkManager, resolved, IPv6, VPN/policy routing and namespace games. Add eBPF only if measured needs justify its portability/security cost.
14. **Live compatibility matrix.** For each game/build, environment and transport record `DETECTED`, `INSPECTED`, `REDIRECT REQUESTED`, `REDIRECT APPLIED`, `RELAY TRAFFIC VERIFIED`, `GAMEPLAY VERIFIED`, `FAILED`, `NOT TESTED`. Evidence must include actual relay traffic, duration, restart and cleanup; respect anti-cheat/service restrictions. Full support requires stable gameplay, not a green UI.

## Incremental module boundaries

Retain C/C++ and kernel mechanisms. Extract only after behavior tests: bounded IPC transport → pure packet/redirect validation → process/socket attribution → TCP decisions → UDP endpoint registry → firewall/session ownership → diagnostics. Keep user discovery/configuration outside the privileged data plane and proprietary decisions in the original client. Public interfaces should define ownership, errors, deadlines and buffer bounds. Each change needs a stated problem, minimal implementation, regressions, relevant checks and documented validation limits.

## Release gate

No stable release until P0 and applicable P1 acceptance criteria pass, unexplained regressions are resolved, supported Linux environments are tested, and every claimed game/transport has L3 evidence. L1/L2 synthetic successes never establish a vendor routing decision or game compatibility. Preserved macOS code and third-party licensing need their own release review; no notices or existing functionality may be silently removed.
