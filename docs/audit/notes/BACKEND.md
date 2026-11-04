# Backend source audit

Baseline: `c0525a74c35fd74c815326d957c21a593a6aaccb`. All `backend/` tracked files were read in full. Line references describe the baseline, before fixes. Findings below are source-confirmed unless explicitly labeled as a hypothesis. No live ExitLag routing or privileged networking was executed for this subsystem audit.

## Inventory, dependencies and behavior

| File | Purpose and dependencies | Implemented behavior / limitation |
|---|---|---|
| `backend/exitlag-netd.c` | Single-threaded native C daemon; Linux `/proc`, libmnl, NFQUEUE, nft CLI, raw sockets | TCP connect-request IPC and IPv4/IPv6 exact-tuple DNAT; bounded UDP endpoint registry; UDP lifecycle/inspection callbacks; restricted IPv4 unchanged-datagram take-and-reinject; authenticated loopback IPC; no-queue synthetic mode |
| `backend/protocol.h` | Packed little-endian protocol shared with Wine shim, x86-64 assumptions | Version 3; 12-byte headers, maximum 131072-byte body, tags, 32-byte session token, TCP/UDP/PID messages; reserved flags documented as zero but not enforced |
| `backend/Makefile` | C compiler, make, libmnl development headers/library | One backend executable; no separate library/unit targets or hardening/sanitizer target |
| `backend/identity-map.example` | User-authored explicit map | Native executable, exact `.exe` argv and Wine-prefix mappings; prefix mapping covers every process in that prefix, not an individual game |
| `backend/nft-setup.sh` | Bash, nftables, root/CAP_NET_ADMIN | Dedicated fixed table, scoped TCP queue before output DNAT, bypass, timed tuple maps; UDP observe/reinject-mark bypass; UDP chain lacks UID scope |
| `backend/nft-teardown.sh` | Bash, nftables, root | Idempotent deletion by fixed table name; no session ownership proof |
| `backend/runtime-guard.sh` | Bash, flock, `/run`, `/proc`, nft, install/readlink | Active-runner lock, orphan PID file, stale-table recovery, timer/helper wait; ownership bound to PID/path, no process start time or pidfd |
| `backend/run-passive.sh` | Daemon, nft setup/teardown, Bash | Root-only scoped passive runner; shared identity args; timed sleep rather than immediate helper failure response; does not acquire lifecycle lock |
| `backend/run-tcp-redirect.sh` | Daemon, nft setup/teardown, runtime guard | Opt-in active TCP; helper before firewall; lock, PID record, helper-crash cleanup; readiness inferred from log |
| `backend/run-udp-observe.sh` | Same plus UDP destination/port/owner substring | TCP active plus UDP observation; no lifecycle lock or helper-crash detection during duration sleep |
| `backend/run-udp-steer.sh` | Same plus raw socket and mark capability | Explicit opt-in narrow IPv4 UDP, one selected eligible endpoint, exact destination scope; does not establish general relay redirection |

## Confirmed findings

### B01 — High: IPC can monopolize the NFQUEUE loop

Evidence: `exitlag-netd.c:547-575`, `1079-1136`, `1168-1236`. `send_frame()` uses blocking `write()` without a deadline. `read_exact()` restarts the full timeout after every fragment. TCP and UDP reply loops restart the full timeout for every nested, unexpected or stale frame. A same-UID connecting process can dribble an incomplete HELLO, and an authenticated malfunctioning/hostile peer can keep a packet callback pending indefinitely. A configured negative `--timeout-ms` is accepted by `atoi` (`2031`) and interpreted by `poll()` as infinite.

Impact: new flows and queued UDP datagrams wait in the only event loop; queue bypass protects absent listeners, not a wedged listener. Overflow fail-open is not a bounded per-packet latency guarantee. Performance impact must be measured, not inferred as a numeric benchmark.

Recommendation: one monotonic absolute deadline covering request/reply and nested messages; nonblocking send/receive with bounded waits; strict positive CLI timeout parsing; tests for byte dribble, endless stale replies/nested messages, blocked writer, EINTR and recovery. Retain synchronous callback semantics during the incremental change.

### B02 — Medium: unauthenticated replacement evicts a working shim

Evidence: `exitlag-netd.c:1195-1200` closes the existing shim and sets the candidate as global before token/version verification at `1239-1250`.

Impact: allowed-UID peers without a token can disconnect an authenticated session; rejected candidates interrupt routing. The session token is a file readable by the owning UID, so it is not a security boundary against all processes of that same UID, despite stronger comments in `protocol.h` and the daemon.

Recommendation: authenticate candidate FD with a total handshake deadline before replacing global state; reject second HELLO after authentication; ensure the event-loop snapshot does not read a replaced descriptor because of an old poll event; test that bad token/version/framing candidates preserve the active connection.

### B03 — Medium: reserved fields and session framing are incompletely enforced

Evidence: `protocol.h:20-24` says header flags must be zero. Framing checks at `exitlag-netd.c:1092`, `1123`, `1211`, `2256` validate only magic/length. A second HELLO at `1098-1103` and `2260-2265` changes the advertised PID and gets an ACK without another version/token check. Sized requests frequently accept `>=` instead of an exact body length. No use is made of `g_shim_authenticated` to gate handlers after accepting a connection.

Recommendation: central frame reader/validator, reject flags and unexpected handshake transitions, define exact/minimum lengths per message explicitly. Do not silently change protocol version or valid ABI struct layout.

### B04 — High: strict identity mapping can be spoofed using argv/environment

Evidence: `exitlag-netd.c:831-856` first checks `/proc/<pid>/exe`, but then compares every argv token to every configured source including canonical native executable paths. Any native process can supply the source as an argument. `801-828` trusts `WINEPREFIX` for any executable. Non-strict path resolution at `889-907` trusts a `.exe` argv token. `tests/test-identity-map.sh` negative control supplies the target Windows path instead of the configured native source and therefore misses this case.

Recommendation: native mapping only against actual executable identity; Wine mappings must verify the runtime executable and approved prefix/image evidence. Keep uncertain cases unresolved; explicit configuration is preferable to fabricated Windows identity. Add adversarial native-source argv, exact configured `.exe` token, environment-only prefix, process exit and PID-reuse cases.

### B05 — High for broad deployment: socket attribution is not a unique connection identity

Evidence: TCP `/proc/net/tcp*` scan at `302-336` parses `rem` but compares only local address/port; PID owner scan at `483-541` ranks `.exe` argv and breaks on first rank 2, without UID/start-time/namespace verification. UDP scan `363-403` also ignores remote endpoint and returns first wildcard port owner, unsafe for shared-port or reuse scenarios. Observed PID ring `119-131` stores only PID and never expires by process start time.

Impact: concurrent same-local-port TCP connections, shared UDP sockets, namespaces, launcher processes, process exit and PID reuse can yield an unrelated identity. This is a confirmed algorithm limitation; specific live cross-application redirection remains untested.

Recommendation: exact family/protocol/source/destination/socket identity; reject ambiguous matches; track UID and process start time, consider INET_DIAG/queue UID metadata/pidfd where validated. Add local socket fixture tests without netfilter, then isolated namespace tests.

### B06 — High for universal UDP: endpoint identity and reconnect state can become stale

Evidence: `1316-1358` reuses endpoint by local sockaddr before checking current socket inode. Rapid close/rebind before reap can inherit previous owner/rules/endpoint. Lifecycle reaper `1391-1410` runs at most once per second and waits two idle seconds before inode absence. Inode lookup fallback returns an existing inode endpoint without updating local address/family or retrying CREATED. `drop_shim()` at `686-692` does not clear/replay endpoint CREATED/CONNECT flags or remote rules. A reconnected shim may receive a datagram for an endpoint never created in that session.

Recommendation: key by socket identity and owner generation; revalidate tuple reuse; reset/replay lifecycle upon a new authenticated session; include reconnect, same-port rebind, wildcard dual-stack and concurrent endpoint regressions before broadening active UDP.

### B07 — Medium: endpoint IDs are not unique across fast daemon restarts

Evidence: `exitlag-netd.c:2151-2157` seeds the ID from realtime seconds, ignoring nanoseconds; two starts in a second reuse the base, contrary to comment `seeded per run, never reused`. Wall-clock rollback also defeats uniqueness.

Recommendation: cryptographically random run nonce plus bounded per-run counter (collision analysis documented), or explicit negotiated session generation. Cloud-safe restart test can reproduce deterministic second-level collisions.

### B08 — Medium: NFQUEUE readiness is logged before kernel acceptance

Evidence: `nfq_config()` and `nfq_set_fail_open()` at `1936-1975` request no ACK and return success solely on netlink send; `nfq_bind_one()` combines send success. `main()` logs `bound NFQUEUE` at `2204` before error replies are read; runners use that log as readiness proof. Failure to bind/fail-open configure can be reported ready, then merely logged by `mnl_cb_run()`.

Recommendation: sequence-numbered bounded ACK exchange for configuration, acknowledge all required flags/queue sizes before readiness, fail startup on kernel rejection. Use mocks for parser/error tests and CAP_NET_ADMIN namespace checks for kernel behavior.

### B09 — Medium: runner/table ownership and cleanup have inconsistent coverage

Evidence: passive and UDP-observe runners import runtime guard but never acquire it (`run-passive.sh:13-57`, `run-udp-observe.sh:14-78`). Their timed runs sleep even after helper death. All runners mark `table_installed=1` only after `nft-setup.sh` exits successfully; that script executes `nft list table` after successfully installing rules (`164-172`), so a post-install listing failure leaves the trap unaware of installed state. `nft-teardown.sh:8-10` deletes by fixed name alone. Runtime guard checks PID+binary path (`runtime-guard.sh:27-54`), not process birth or nft table generation.

Impact: SIGKILL of a runner cannot execute shell cleanup; active guard recovers on next launch but does not remove firewall immediately. It is incorrect to promise no persistent state under every crash mode. nft queue bypass is useful but residual NAT entries/conntrack must be considered separately.

Recommendation: common guard/lifecycle for all runners; explicit session ownership marker; atomic install result handling; trusted watchdog/service ExecStopPost for crash recovery; process start-time validation. Add command-mocked rootless shell tests plus namespace lifecycle tests.

### B10 — High confidentiality concern: UDP payload bytes are logged by default

Evidence: `hex_head()` at `957-966` emits first 32 payload bytes; `handle_udp_post()` at `992-1019` logs bytes and payload hash; `observe_udp_packet()` at `1585-1650` logs bytes and endpoints. Root daemon opens log via `fopen(..., "a")` (`2080`) with caller umask, follows symlinks, and root-run scripts default to user-checkout runtime paths.

Impact: private datagram content/identifiers can enter diagnostics and shared-readable files; path symlink replacement can target another writable-as-root file when root runs from a user-controlled checkout. The exact exploitability depends on deployment path ownership, which needs installer review.

Recommendation: never log datagram content by default; explicit bounded opt-in capture only in private runtime storage. Open root diagnostics with no-follow/exclusive secure ownership rules, mode 0600 and safe rotation; do not log tokens. Document account-level rather than process-level token trust.

### B11 — Medium: IPv6 extensions and malformed/truncated packets are not parsed consistently

Evidence: `on_packet()` at `1744-1760` assumes L4 immediately after 40-byte IPv6 header and tests only its `next header`. nft `meta l4proto` can identify TCP/UDP beyond extension headers, so queued packets with extensions fail open without inspection. IPv4 total length/fragment flags and TCP data offset are not checked by daemon. UDP advertised payload length is silently clamped to capture length (`1521-1524`), allowing a truncated callback payload to be treated as a complete datagram by the active path.

Recommendation: small independently tested bounded packet parser; reject unsupported extension/fragment forms for active decisions; do not reinject truncated datagrams; retain fail-open. Test extension chains, fragments, invalid lengths, odd payload checksums and max-length datagrams under ASan/UBSan.

### B12 — Medium: firewall input scope and UID boundaries need stronger validation

Evidence: `nft-setup.sh:51-59`, `67-76` insert supplied strings into an nft batch without address parsing, queue values are also unvalidated. Root-invoked script environment is trusted command input, but malformed values should never be able to add statements. Optional `EXL_USER_UID` scopes TCP chains (`150`, `157-158`) but not UDP output/input chains (`110`, `117`). `--udp-exe` is only a case-insensitive substring (`1543`), not proof of ownership or exact identity.

Recommendation: parse exact IPv4/IPv6 addresses, strict decimal queue/port/UID ranges, refuse accidental all-UID active capture, bind active authorization to verified game owner. Input scope includes receive direction, so ordinary `meta skuid` at input is not a sufficient socket-identity design by itself.

## Confirmed capability gaps (not new game failures)

- TCP IPv4/IPv6 exact tuple NAT exists, but no TCP established/closed callback emission, per-flow manager, deduplication of retransmitted SYN decisions, or daemon-side connection state exists. Conntrack owns data-plane lifecycle.
- IPv6 family-preserving redirect is implemented; IPv4-to-IPv6/IPv6-to-IPv4 callback targets are refused. IPv6 extension-header flows are not inspected.
- Active UDP supports one exact eligible endpoint in production runner. It requires one unchanged IPv4 SEND post with one usable remote rule, no controls/options/mutation; inbound unchanged RECEIVE passes original packet. It is **not** general UDP relay redirection.
- UDP IPv6 inspection exists for direct next-header UDP, but active IPv6 raw reinjection does not. Multiple remote rules are stored (16) and endpoints bounded (2048), but dynamic multi-server transport support is unverified and constrained.
- No bounded backpressure mechanism between IPC callbacks and packet processing; serialized callbacks, `/proc` scans, synchronous per-redirect fork/exec nft, datagram allocations and flushed per-packet logs are likely bottlenecks. No performance improvement is claimed without reproducible measurement.
- UDP reaping can scan `/proc/net/udp*` once per endpoint per second and synchronously emit CLOSED callbacks; endpoint table linear scans increase control-plane cost with concurrency.
- No dedicated NetworkManager, systemd-resolved, VPN coexistence or netns-owned socket attribution validation is present in backend. Interaction is untested rather than known-broken.

## Architecture recommendation

Keep libmnl/NFQUEUE/nftables; no evidence currently justifies eBPF or a language rewrite. Extract in small steps: bounded IPC transport/frame validation; pure packet parsing/checksum/redirect validation; verified process identity; TCP tuple decisions; socket-generation UDP endpoint registry; firewall ownership/session lifecycle. Privileged packet application must remain separate from user configuration/discovery and the official client callback provider.

## Test opportunities and acceptance criteria

Cloud-safe: compile native tests with libmnl available; `--no-queue` authentication/framing/deadline/restart tests against actual daemon; local proc/socket attribution fixtures; pure packet/checksum/redirect/UDP registry unit tests; sanitizer builds. A synthetic provider must be labeled synthetic and must not count as actual ExitLag routing.

Privileged isolated: network namespaces with nft/NFQUEUE, original destination and reverse NAT, IPv4/IPv6, concurrent process distinction, UDP bidirectionality and port reuse, queue saturation, helper crash/restart and table ownership. Skip with capability reason when unsupported; never run global firewall tests on the cloud host.

Live: official client + user's account/subscription + Linux games; measure DETECTED, INSPECTED, REDIRECT REQUESTED, REDIRECT APPLIED, RELAY TRAFFIC VERIFIED, GAMEPLAY VERIFIED independently. No live state is established by this source audit.
