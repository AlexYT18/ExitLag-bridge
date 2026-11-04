# Backend hardening implementation record

This document describes the implemented changes following the complete source audit. Baseline findings and original line references remain in `BACKEND.md`; an audit finding is not proof that its entire subsystem is now production-ready.

## Bounded IPC transport

`backend/ipc_transport.c` and `.h` isolate socket framing and deadline behavior from packet processing. All reads and writes use nonblocking socket operations with `poll()` and an absolute `CLOCK_MONOTONIC` deadline. Header, body and send parts share one deadline. TCP and UDP request/reply operations additionally share that deadline through nested PID/UDP-state/post messages and ignored stale tags. EINTR and byte fragmentation cannot restart the budget. Backpressure cannot cause an unbounded blocking write. A partial frame, timed-out operation or framing failure disconnects the shim so its remainder is not interpreted as a fresh header.

The configured RPC timeout is restricted to decimal integers in `1..60000` milliseconds, with the existing default of 300 milliseconds. Candidate authentication has a separate total two-second budget. Unsolicited complete frames have a 200-millisecond read budget. These are bounded synchronous operations, not a fully asynchronous transport: a candidate can still delay the shared event loop for at most its handshake budget, and packet processing remains serialized. Queue saturation and performance remain separate validation obligations.

An incoming candidate is authenticated before replacing the current authenticated connection. Wrong UID, token, version, framing or an incomplete HELLO does not evict the active peer. Poll events captured for an old descriptor cannot be applied to its replacement. A rejected candidate also cannot trigger an additional synthetic self-test on the existing peer.

The protocol version and packed struct ABI remain version 3. Header flags must be zero, HELLO must be exactly the fixed-size record, fixed RPC replies must match their exact size, and PID-resolution requests must have exactly their defined size and zero reserved field. A second HELLO within an authenticated session is refused. Previously tolerated trailing HELLO/reply bytes are now malformed; old tests expecting that tolerance must explicitly be updated to the strict contract. The token protects account ownership and session freshness, not process identity within the same UID; source comments now state this honestly.

## Private diagnostics

UDP diagnostic lines retain event IDs, endpoint addresses, lengths, callback counts and decisions. Payload prefixes and payload hashes have been removed. This is metadata-only diagnostics, not an opt-in packet capture feature. Endpoint metadata and executable paths can still be private: logs should be reviewed and redacted before sharing.

A requested log path is resolved through anchored directory descriptors, rejecting symlink components and `..`. The final file is opened with `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`; FIFOs cannot stall startup. Before any diagnostic write, `fstat()` requires a regular single-link file owned by the helper's effective UID. File permissions are set to 0600. Existing harmless files owned by that UID are accepted and made private. Root does not accept an existing user-owned log. Rotation retains the originally opened directory descriptor, verifies the named inode against the open file, renames within that directory, and exclusively creates a private replacement. If replacement creation fails it retains the already-open private inode rather than following a substituted path.

Residual limitation: filesystem failures or pathname substitution can prevent rotation; size limits remain best effort under those error conditions. Directory ownership, deployment paths and sandboxing are still important. This change does not make all root-run user-checkout scripts a hardened installed service.

## nft executable portability

The child executing an exact TCP DNAT update tries trusted absolute `/usr/sbin/nft` and `/usr/bin/nft` paths. It never searches caller-controlled `PATH`. Packagers and isolated test builds may specify an absolute compile-time `EXL_NFT_PATH`; there is no runtime environment override. This supports Debian/Ubuntu's sbin packaging and Arch's bin packaging while keeping command arguments generated from parsed addresses and ports.

## Automated verification added

- `tests/ipc-transport-test.c`, invoked by `make -C backend check-ipc`: actual socketpair frame round trips, empty payload, invalid magic/flags/size, fragmented delivery, slow byte delivery, shared header/body deadline, blocked writer, EINTR and peer close. It does not need libmnl or root.
- `tests/test_backend_ipc.py`: real `--no-queue` daemon tests, using only loopback IPC and synthetic callback replies. Covers authentication, non-destructive candidate rejection, legitimate replacement, malformed framing and sizes, second HELLO, partial/slow frame timeout, stale/nested callback deadline, invalid timeout options, private log modes/rotation and rejected filesystem objects. A synthetic UDP POST with a canary verifies that its actual diagnostics do not emit payload bytes or hashes.

Suggested commands:

```sh
make -C backend
make -C backend check-ipc
python3 -m unittest discover -s tests -p test_backend_ipc.py -v
# Suitable sanitizer builds (LeakSanitizer may require additional runtime support):
make -B -C backend CFLAGS='-O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer'
make -C backend check-ipc CFLAGS='-O1 -g -Wall -Wextra -fsanitize=address,undefined -fno-omit-frame-pointer'
ASAN_OPTIONS=detect_leaks=0 python3 -m unittest discover -s tests -p test_backend_ipc.py -v
```

Actual executed results and environment details are recorded in the main audit validation report. The tests are account-free mechanism checks; their presence does not establish live ExitLag routing or game compatibility.

## Remaining networking risks

The changes do not broaden active UDP, claim real ExitLag callback decisions, establish game support or prove live relays. UDP socket generation/reconnect state, exact process attribution including PID reuse, complete IPv6 extension parsing, NFQUEUE kernel ACK readiness, common firewall ownership/lifecycle across all runners, conntrack cleanup, saturation metrics and real network-tool coexistence remain separately tracked. Tests using a synthetic provider establish only the tested local mechanism.
