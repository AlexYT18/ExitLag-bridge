# Architecture

This describes the Linux implementation and separates its mechanisms from
historical live observations. It does not establish compatibility with every
game or client build. See the [initial audit](audit/INITIAL_AUDIT.md),
[compatibility record](compatibility.md) and [roadmap](audit/ROADMAP.md) for
evidence boundaries and work still to validate.

The project replaces exactly one thing: the Windows packet-interception backend
that ExitLag's client talks to. Everything else — login, subscription, relay
selection, route optimisation, the UI — remains ExitLag's own code, running
unmodified under Wine.

## The stack

```text
       ExitLag.exe + libexitlag.dll   (official, unmodified, under Wine)
                    |
                    |  imports nfapi.dll
                    v
       nfapi.dll compatibility shim   (shim/nfapi/nfapi_stub.cpp)
                    |
                    |  loopback TCP, 127.0.0.1:51900
                    v
       exitlag-netd                   (backend/exitlag-netd.c, runs as root)
                    |
                    |  libmnl / NFQUEUE verdicts, nftables map updates
                    v
       nftables `inet exitlag`        (dedicated table, created and destroyed
                    |                  by this project only)
                    v
       TCP destination rewrite / UDP take-and-reinject
```

The transport uses loopback TCP because the Wine 11.17 `ws2_32` family map
used during development lacked `AF_UNIX`. Loopback alone is not authentication:
the helper also checks the peer uid and a per-session token. See the
[security review](security-review.md) and [RPC surface](rpc-surface.md).

## Control plane vs data plane

**Control plane — ExitLag's, untouched.** Authentication, subscription checks,
relay selection, route analysis and optimisation, the connection list, and the
per-connection decision of *whether and where* to redirect. The shim never
invents a routing decision; it only reports facts and applies what ExitLag
returns.

**Data plane — this project.** Seeing packets, attributing them to a process,
asking ExitLag what to do, and carrying out that answer with nftables.

The boundary is the `nfapi` ABI. ExitLag calls into the shim to configure
filtering and receives callbacks; the shim forwards those events to the helper
and returns the helper's observations. Nothing in the helper knows what a relay
is.

## TCP flow

Filtering rules ExitLag installs are deliberately broad:

```text
nf_setRulesEx.rule protocol=6(TCP) processId=0 direction=2(OUT)
  filteringFlag=0x10(INDICATE_CONNECT_REQUESTS) processName=""
```

`processId=0` and `processName=""` make this vendor rule broad; the routing
decision is deferred to a per-connection callback. Native queue scope and exact
identity mappings provide additional boundaries. Packaged user-scoped routing
must not be confused with the broader developer runners.

A redirected connection goes like this:

1. `output_queue` (filter hook, priority -150) queues **only** the first SYN of
   a new outbound TCP connection. Loopback is skipped, and `ct status dnat` is
   skipped so an already-redirected flow is never re-examined.
2. The helper attributes the socket to a PID, then calls the shim.
3. The shim runs ExitLag's `tcpConnectRequest` callback. ExitLag either leaves
   the address alone or rewrites it to one of its local proxy endpoints and sets
   `filteringFlag` to `0x210` (redirect).
4. On a complete address+port mutation, the helper installs one exact element
   into the family's map — `tcp_redirect_v4` or `tcp_redirect_v6` — keyed by the
   full 4-tuple, with a 10-second timeout. The family must match, the port must
   be nonzero, and unspecified, broadcast (IPv4) and multicast addresses are
   rejected. By default the target must be loopback: `127/8`, `::1`, or
   IPv4-mapped `::ffff:127/8`. A rejected mutation arms no redirect.
5. The SYN is ACCEPTed and continues to `output_nat` (nat hook, dstnat
   priority), where the map performs the DNAT. Conntrack carries the translation
   for the rest of the connection, so the steady-state data path is untouched.

The queue sits after conntrack but before NAT specifically so the map element
can be installed while the SYN is still suspended.

Historical WoW observations reported a connection whose application-visible
game-server endpoint was translated to an ExitLag listener on `127.0.0.1`.
That observation is not a new live result for the current checkout.

## UDP flow

This backend's active UDP path uses take-and-reinject rather than the TCP DNAT
map. It supports a narrow IPv4 callback contract; it is not general UDP support.

Two chains (`output_udp_observe`, `input_udp_observe`, filter priority -10)
queue datagrams in both directions. The helper tracks endpoints keyed by a
synthetic 64-bit id and reports lifecycle events (`udpCreated`,
`udpConnectRequest`) plus each datagram to ExitLag.

For a supported outgoing callback, the posted remote address and payload must
match the original datagram and the recorded remote rule must match. After a
successful raw send carrying mark `0x584c0001`, the helper drops the original.
A dedicated rule accepts that mark so the reinjected copy does not re-enter
the queue. The supported receive path accepts the original incoming datagram;
unsupported callback shapes leave it unchanged.

Endpoint state is bounded and self-expiring: at most 2048 endpoints, 16 unique
remote-address rules each. An endpoint is released when its socket inode
disappears (checked once idle for 2s) or unconditionally after 60s idle, with a
lifecycle event emitted to ExitLag so its own per-endpoint state is released too.

## Process attribution and identity

The helper attributes a queued packet to a socket inode, then to a holding PID
via `/proc`. What that PID *is* differs by case, and this is the subtlest part
of the system:

- **Native Linux process** — the PID is the process itself. `/proc/<pid>/exe` is
  its real executable.
- **Wine or Proton** — during the recorded SYN-time experiments, the socket
  could be held only by the prefix's `wineserver`, before the game acquired its
  fd. A shared wineserver executable does not identify a particular game;
  separate prefix mappings address that case.
- **Inside ExitLag's own prefix** — ExitLag resolves its own Wine PIDs through
  `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL)`, which works only within its
  own prefix.

The shim asks the helper to resolve any PID it does not recognise as a Windows
one (`nf_getProcessNameFromKernel` → nested `RESOLVE_PID` request on the same
connection, served while the helper is already waiting for that callback's
reply).

### Identity mapping

`exitlag-netd --identity-map FILE` loads exact native `SOURCE<TAB>WINDOWS_PATH`
pairs and executable-bound prefix `SOURCE<TAB>WINDOWS_PATH<TAB>OWNER_EXE` rows.
Two source forms are accepted:

| Source form | Matched against | Use |
|---|---|---|
| absolute host path | canonical `/proc/<pid>/exe` | native Linux game |
| `wineprefix:<dir>` plus mandatory owner column | canonical absolute `WINEPREFIX` and exact kernel-reported owner executable | explicit Wine/Proton prefix scope; not Windows image proof |

An arbitrary `.exe` argv token is not an accepted mapping source. Loading a map
enables strict mode: unmapped processes retain their genuine identity rather
than acquiring a configured game's Windows identity. See
[process identity translation](process-identity-translation.md) for the current
mapping and attribution rules. A matching identity still does not prove that
ExitLag returned a redirect or that gameplay works.

Both sides of a comparison pass through `realpath()`, which matters in practice:
Proton sets `WINEPREFIX` with a trailing slash while a user writes the entry
without one.

## Runtime ownership

`backend/runtime-guard.sh`, sourced by the active runners, makes the backend
single-owner:

- an `flock` on `/run/exitlag-linux/backend.lock`; a second runner refuses to start
- a pidfile recording the helper PID **and** its resolved binary path, so a
  recycled PID belonging to an unrelated process is never signalled
- on startup, an orphaned helper from a killed runner is terminated and its
  table removed
- a table with no verifiable project ownership is **refused, not deleted**
- the lock fd is closed in spawned children, so a SIGKILLed runner cannot leave
  its helper holding the lock

## Heartbeat and reconnect

The helper sends `EXL_MSG_PING` every 2s; the shim replies `PONG`. The shim sets
5s send/receive timeouts on its socket and retries a lost connection every 2s.

This exists because Wine can leave a loopback connection *established* after the
helper is gone, which would otherwise pin the shim's thread forever on a peer
that will never answer. The timeout converts that into the ordinary fail-open
reconnect loop.

## Fail-open semantics

The intended fallback for an unresolved routing decision is to accept the
queued packet unchanged. Attribution misses, absent usable shim replies,
invalid TCP targets, failed map updates and unsupported UDP contracts use that
fallback. The default callback timeout is 300 ms; framing and deadline behavior
must be assessed with the transport tests for the exact source revision.

`queue ... bypass` lets packets pass when no queue listener is bound. It does
not by itself cover a full queue or a listener that is alive but stalled.
Already established DNAT connections retain conntrack state; losing their
ExitLag proxy does not migrate them to a direct connection. Helper failure,
proxy failure and survival of an existing relay session are different checks.
See [runtime hardening](runtime-hardening.md) for the recorded test scope.

## Cleanup and recovery

The project's nftables rules and maps live in the dedicated `inet exitlag`
table, so deleting that table removes that firewall surface in one operation.
It does not erase existing conntrack translations. Runners install the table
after helper startup and use EXIT/INT/TERM traps for ordinary cleanup.
`runtime_guard_wait` waits for the helper or a timer and returns when the
helper exits so the runner can clean up.

SIGKILL cannot execute a trap. A killed runner can leave an orphan helper and
table; `runtime_guard_acquire` attempts recovery on the next authorized start
using its recorded ownership state. A table without verifiable project
ownership causes refusal instead of automatic deletion. The historical
hardening scenarios test these cases separately; they are not a guarantee of
cleanup after every machine or process failure.

## Wine-specific compatibility

- **Crash guards.** ExitLag imports 11 functions Wine does not export (8 in
  IPHLPAPI, 3 in POWRPROF). Wine resolves a missing import to a stub that raises
  the non-continuable `EXCEPTION_WINE_STUB` (0x80000100), which kills the
  process — this is what crashed the client on the PC Boost and DNS pages. The
  shim patches the main image's IAT at process attach so those return
  `ERROR_NOT_SUPPORTED` instead. See `docs/wine-stub-crash-guards.md`.
- **WMI.** ExitLag queries `Win32_LogicalDiskRootDirectory`, which the tested
  Wine build lacked. Packaged setup prepares a patched WMI payload; developer
  setup can use the project-local Wine build. Neither requires modifying system
  Wine. See [Wine setup](wine-setup.md) and the [installer guide](../installers/README.md).
- **Rendering.** The Qt UI needs `QSG_RHI_BACKEND=opengl` under this Wine build.
- **`nfextlag`.** A compatibility surface for the driver-name ExitLag expects.

## Status of each behaviour

**Historical development observations**

The following were reported during development. Private traces and original
machine state are not included in this source snapshot, and this list is not a
rerun against the current packaged installer:

- TCP destination rewrite, including real WoW world connections
- UDP take-and-reinject (20/20 payload hashes matched, 0 ENOBUFS)
- crash guards (11/11 installed; previously fatal pages now survive)
- native Linux process identity translation
- ExitLag associating a live session for a process it cannot itself see: its
  UI showed the native Dota 2 session, matching endpoint, without a restart
- separate Wine prefix routing, with an unmapped control not routed
- Proton routing including pressure-vessel containment
- helper crash, runner SIGKILL recovery, reconnect, version mismatch,
  stale-table refusal and an unreachable destination in the scoped hardening
  harness; see [runtime hardening](runtime-hardening.md)

**Optional / debug only**

- `EXITLAG_NFAPI_TRACE=1` — full per-call argument trace. Production logs only
  lifecycle events and explicitly unsupported calls.
- `EXITLAG_NFAPI_SUCCEED`, `EXITLAG_NFAPI_EXTVER` — research overrides for the
  built-in export table and extensions version. **Not required in production**
  and not consulted unless set.
- `EXITLAG_NFAPI_INJECT` — synthetic callback injection, research only.
- `--self-test`, `--udp-active-once`, `--udp-active-index`, `--udp-exe` — narrow
  experiment scoping.

**Known limitations**

- `wineprefix:` maps an entire prefix to one game identity. Correct for Proton
  (one prefix per title); too coarse for a hand-made prefix holding several games.
- Strict mode applies to in-prefix games too. An unmapped game must not be
  assumed to receive the configured Windows identity.
- TCP rewriting handles both families. Active **UDP** rewriting is IPv4 only.
- The IPv6 TCP path is proven against a synthetic peer, not a live title: no
  game observed here has yet been given an IPv6 route by ExitLag, so the
  decision stage has never exercised it. See `docs/ipv6-active-rewrite.md`.
- Redirection method must stay Automatic/WFP. NDIS needs `\\.\NDEXTLAG`.
- Route analysis protocol should be TCP; ICMP works but is widely rate-limited.
- No completed physical link down/up test or long-duration soak beyond the
  historical ~25-minute session is recorded here. These remain validation items,
  not working-feature claims.
