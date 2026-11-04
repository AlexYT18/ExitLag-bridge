# PEAK: local ExitLag validation

Target: Arch Linux x86_64, Steam + Proton. This procedure requires the official
ExitLag client, the user's legitimate subscription and PEAK installed locally.
The Cloud development environment has no configured client, subscription or
game. **All live stages below are NOT TESTED for the current branch.** Earlier
user screenshots are discovery context, not a current routing test.

## Preparation

1. Install the newly built portable package using [the Arch guide](arch-linux.md).
   Record the package SHA-256 and its build revision. Updating a source checkout
   does not update an already installed launcher or its private Wine prefix.
2. Open Bridge as the ordinary game user. Complete official-client setup and
   sign in inside that client. Keep account data and subscription information
   local; the project does not need these secrets.
3. Start PEAK through Steam/Proton and open an actual network session. In Bridge,
   use **Add / manage games → Add running game**. Search for PEAK or its Steam
   AppID, select the socket-owning process and the actual mapped game image.
   Refresh if the process changed. Do not select Steam or wineserver merely
   because they also own sockets.
4. Save the verified mapping. A prefix mapping authorizes the selected runtime
   throughout that prefix; see [game selection](game-selection.md). Stop routing
   before changing mappings. For the UDP trial, explicitly enable
   **Experimental UDP** before launching the helper/client.

## Evidence by stage

Record the source revision, kernel, Proton/Wine version, ExitLag version, game
build, transport and test duration. Keep diagnostics private and redact local
paths, addresses and identifiers before sharing them. Do not publish packet
captures or account logs by default.

| Stage | Required observation | Current branch live result |
| --- | --- | --- |
| DETECTED | Official ExitLag recognizes the intended PEAK identity | NOT TESTED |
| INSPECTED | Current game-owned TCP/UDP flows reach actual client callbacks | NOT TESTED |
| REDIRECT REQUESTED | The official client issues a usable redirect/post for those flows | NOT TESTED |
| REDIRECT APPLIED | Backend applies that exact decision to current game packets | NOT TESTED |
| RELAY TRAFFIC VERIFIED | Bidirectional game traffic is observed through the selected real service relay | NOT TESTED |
| GAMEPLAY VERIFIED | Sustained multiplayer gameplay, reconnect and cleanup succeed | NOT TESTED |

Select PEAK and apply routing inside official ExitLag. Compare a direct session
and a routed session under the same conditions. Reconnect the game between
trials so existing sockets/conntrack state cannot be mistaken for a new route.
For TCP, distinguish a local client proxy connection from the proxy's actual
upstream relay connection. For UDP, distinguish the original destination from
the posted target and verify replies as well as sends. A byte counter, a GUI
entry or a synthetic local relay is insufficient to establish service routing.

If inspection occurs without a redirect, record that exact stage and investigate
the actual callbacks, identity and client version; do not fabricate a response.
If game traffic remains direct because a packet or SDK operation is unsupported,
record the limitation. Do not disable security checks to obtain a green result.

Finish by stopping routing, checking project-owned firewall cleanup and testing
direct connectivity again. Include a client restart and a multiplayer reconnect
before claiming stable gameplay. Record failures and duration explicitly; this
document sets no arbitrary duration that automatically certifies support.

See [routing stages](pipeline-stages.md), [UDP constraints](udp-multi.md) and
[shim teardown requirements](shim-lifecycle.md). Respect the game's anti-cheat
and the service's account and subscription restrictions.
