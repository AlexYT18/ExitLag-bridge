# The helper's privileged RPC surface

The Linux helper runs with the privileges needed for NFQUEUE and nftables.
[Authentication](security-review.md) controls the peer uid and session token;
this document describes the operations reachable after authentication. Inputs
from an authenticated peer remain untrusted. See the
[initial audit](audit/INITIAL_AUDIT.md) and [roadmap](audit/ROADMAP.md) for the
review findings and outstanding validation.

## Wire messages

`backend/protocol.h` is the source of truth for message values and layouts.
The principal peer-to-helper messages are:

| Message | Value | Peer-controlled data | Operation |
|---|---|---|---|
| `HELLO` | `0x0001` | version, claimed Windows PID, session token | establish an authenticated session |
| `PONG` | `0x0004` | empty payload | heartbeat response |
| `TCP_CONNECT_REPLY` | `0x0011` | tag, flags, destination sockaddr | request a per-flow DNAT element |
| `RESOLVE_PID_REQ` | `0x0020` | tag, Linux PID | request process identity resolution |
| UDP lifecycle/connect/datagram replies | `0x0041`, `0x0043`, `0x0045`, `0x0049` | tag and callback results | finish an outstanding callback |
| `UDP_POST` | `0x0046` | event tag, endpoint, remote address, payload | participate in the supported UDP reinjection contract |
| `UDP_STATE` | `0x0047` | event tag, endpoint, flags and remote-rule data | record bounded endpoint state |

Frames have a 12-byte EXL1 header and a maximum payload of 128 KiB. A reply's
tag must match the outstanding request before its result is used. Message
handling depends on connection state and the outstanding callback; these
messages are not an arbitrary-command API. No wire field is evaluated as a
shell command or executable path.

The current helper transport uses absolute monotonic deadlines for complete
frame reads/writes and callback exchanges, including nested messages. The
default callback budget is 300 ms and the handshake budget is 2 seconds. This
describes IPC waits, not all process attribution, nft execution or kernel queue
work. Malformed framing, unknown messages, handshake state and stale replies
still need negative tests for the exact source revision. The
[initial audit](audit/INITIAL_AUDIT.md) records the original implementation's
transport limits; use the current transport tests when assessing changes.

## TCP destination rewrite

A redirect requires active TCP routing, a changed destination and a mutation
verdict for the observed flow. Validation is family-specific:

| Check | IPv4 | IPv6 |
|---|---|---|
| Wire family matches original flow | `2` (`AF_INET`) | `23` (Windows `AF_INET6`) |
| Nonzero destination port | required | required |
| Invalid destinations | unspecified, broadcast, multicast | unspecified, multicast |
| Default allowed target | loopback `127/8` | `::1` or IPv4-mapped `::ffff:127/8` |
| Padding-only change | no redirect | no redirect |

The map key is the original source/destination address and port, not a broad
subnet or arbitrary nftables expression. A map element expires after 10 seconds;
conntrack can retain an established translation afterward. No wire message
supplies a rule, chain or command to execute.

`--allow-remote-redirect` deliberately relaxes the loopback restriction for
experiments. The production runners do not pass it. Historical real-client
redirects targeted the local ExitLag proxy. The IPv6 application mechanism has
a synthetic test; no live game receiving a vendor IPv6 redirect is recorded.
See [IPv6 active rewrite](ipv6-active-rewrite.md).

## PID resolution and identity

By default, resolution requests are limited to PIDs previously reported by the
helper. Out-of-scope requests return an empty path. The observed-PID set and
process lifetime must be considered when assessing PID reuse; prior observation
is not proof that a numeric PID still identifies the same process.

`--allow-any-pid-resolve` broadens that scope for IPC-only harnesses and is not
passed by the production runners. The identity map is read from a helper
command-line file, not received over the wire. Exact mappings and Wine-prefix
attribution are described in [process identity translation](process-identity-translation.md).

## UDP reinjection

Active UDP steering is IPv4-only and accepts a narrow callback contract. The
posted remote address must match the original destination byte-for-byte, the
posted payload must match the original datagram, and the expected endpoint and
remote-rule state must be present. The outgoing original is dropped only after
a successful supported reinjection; the supported incoming path accepts the
original packet. Unsupported shapes fall back to accepting it unchanged.

Payload length is bounded by the frame limit and the 65507-byte UDP payload
limit. Endpoint state is bounded to 2048 endpoints and 16 unique remote rules
per endpoint, with idle/socket-lifetime retirement. Bounded allocation does not
prove immunity to CPU, queue or socket pressure.

## Residual authority

An authenticated peer can influence which local listener receives eligible
outbound traffic. A process able to read the owning user's token can impersonate
the shim. Restricting the DNAT destination to loopback prevents a direct
non-loopback target in this API; it does not prevent a local proxy from forwarding
traffic elsewhere. Same-user token access and local proxy authority remain
part of the trust boundary.

## Checks and their limits

`tests/rpc-surface-test.sh` combines policy/source checks with malformed-request
and PID-resolution cases over authenticated IPC. Its source assertions alone do
not demonstrate real packet redirection. `tests/ipv6-redirect-test.sh` exercises
the IPv6 application path with netfilter and a synthetic peer. IPC negative and
framing suites exercise their respective transport cases. Use each suite's
actual output and requirements; historical counts are not a current result.
