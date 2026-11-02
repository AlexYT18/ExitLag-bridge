# Routing stages and evidence

Game recognition, callback delivery, the routing decision and packet steering
are separate stages. A result at one stage does not establish success at the
next. The bridge implements stages 2 and 4, and its compatibility behavior can
also affect what the official client observes and decides.

```text
1. DETECTION          does the official client recognize the game?
        |                 Its process enumeration is limited by its Wine prefix.
        v
2. INSPECTION         does traffic reach the routing callback?
        |                 Bridge attribution, identity mapping and nfapi events.
        v
3. DECISION           does the official client return a usable redirect?
        |                 Vendor logic consumes the supplied callback data.
        v
4. APPLICATION        is that redirect applied to real packets?
                          Native steering, reverse translation and cleanup.
```

A dashboard session or byte counter can be evidence of inspection without a
redirect. A redirect log can show an attempted decision without demonstrating
bidirectional relay traffic or stable gameplay. Failures require investigation
across this boundary; they cannot be assigned to the vendor solely because a
bridge test passed.

See the [initial audit](audit/INITIAL_AUDIT.md),
[compatibility record](compatibility.md) and [roadmap](audit/ROADMAP.md).

## Historical per-game observations

These summarize the earlier Linux development reports. The original private
captures and machine state are not included in this checkout. These are not
new measurements of the current installer, and the counts below do not imply
present-day compatibility.

| Game | Detection in vendor process list | Inspection | Redirect reported | Applied traffic | Gameplay result |
|---|---|---|---|---|---|
| WoW Classic Era, Wine | reported | reported | reported | TCP world traffic; separate UDP login-probe experiment | Working on the maintainer's original Arch setup |
| Dota 2, native Linux | not observed | UI session/metering reported | none in the recorded session | not established | Detection/inspection only |
| Minecraft Java, native Linux | not observed | reported | reported | relay traffic reported | Sessions disconnected |
| Tibia, native Linux | not observed | reported | none in the recorded session | not established | Detection/inspection only |

### WoW Classic Era

Historical TCP tests reported translation to the official client's local proxy
and established world-server sockets through gameplay. The separate active UDP
experiment reported 20/20 matching payload hashes and no ENOBUFS errors for the
tested datagrams. The report identifies these UDP packets as realm-list latency
probes at login, not in-world UDP gameplay. Neither result proves UDP support
for another title.

### Dota 2

The earlier report describes a dashboard session with the expected endpoint and
ping, despite the native process being outside ExitLag's Wine prefix. In that
sample, 12 `udpConnectRequest` returns offered no address mutation, with zero
`nf_udpPostSend` calls and no remote-address rules while 8515 incoming datagrams
were observed. Working relay steering was not established.

Changing the selected region reportedly did not change that sample's outcome.
Steam Datagram Relay was proposed as an explanation, but the experiment does
not establish the vendor's internal reason or exclude a bridge compatibility
problem.

### Minecraft Java

The earlier report describes six steered connections across four servers and
803 KB carried through a relay. All sessions disconnected. The private capture
was reported to show FINs from the ExitLag side after about 4.5 seconds, with
reverse NAT apparently correct in that sample.

Disabling the route while leaving the backend running reportedly allowed direct
play. This comparison narrows the failure to the routed configuration; it does
not identify whether the cause is vendor policy, a callback/transport mismatch,
or another bridge defect. A comparable Windows control and a fresh reproducer
are not recorded here. Minecraft remains **unstable**, not supported gameplay.

### Tibia

The earlier discovery experiment distinguished the launcher from the actual
network-owning game client. Mapping the launcher alone translated its HTTPS
traffic, which did not establish routing for the game.

With the client mapped and in-world, the recorded flows used IPv6 on port 443;
the callback returned a filtering flag without a destination address. No usable
redirect was available to apply in that experiment. Adding IPv6 TCP rewrite
does not by itself change that observation or establish Tibia support.

### IPv6 TCP mechanism

`tests/ipv6-redirect-test.sh` supplies a synthetic authenticated peer to the
production helper and checks an IPv6 connection, DNAT, reverse translation,
invalid-target refusal and teardown. Historical results are described in
[IPv6 active rewrite](ipv6-active-rewrite.md). No real game receiving an
ExitLag-provided IPv6 redirect is recorded here.

## How to extend the record

For each new result, record the source/artifact revision, OS/kernel, client and
Wine versions, game build, transport and launch method. Identify each stage
actually observed, distinguish logs from packet/relay evidence, and record
session duration, restart and cleanup outcomes. Mark skipped or untested steps
explicitly. Use redacted summaries rather than private captures or account data.
