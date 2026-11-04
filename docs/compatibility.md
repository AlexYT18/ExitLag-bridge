# Compatibility and evidence

An ExitLag dashboard entry does not prove traffic is being relayed. Keep user
reports, automated tests and observed game connections distinct.

Client versions are a separate compatibility boundary. The
[5.24.0 review](exitlag-updates.md#client-5240-review--2026-11-02) records static
import checks and fresh-prefix configuration on macOS. Login and live routing
with 5.24.0 remain untested; the earlier game results below are not new-version
certification.

The results below are earlier maintainer/development reports, not new live-game
runs from the source audit. The public checkout omits private captures and
configured account state. See the [initial audit](audit/INITIAL_AUDIT.md),
[routing stages](pipeline-stages.md) and [roadmap](audit/ROADMAP.md) for the
evidence boundaries and work still to perform.

| Game | Platform | Recorded result | Tested scope |
|---|---|---|---|
| World of Warcraft Classic Era | **Arch Linux, x86_64** | Working — maintainer verified | Real gameplay on Arch Linux with the original bridge. |
| World of Warcraft Classic Era | macOS / Apple Silicon | Working | Stable gameplay and bidirectional world-server traffic through ExitLag. |
| World of Warcraft Forever | macOS / Apple Silicon | Partial | Relayed character-selection connection; world entry was unavailable before release. |
| Minecraft Java Edition | Native Linux | Unstable | Traffic was relayed, but sessions disconnected; not considered working gameplay. |
| Dota 2 | Native Linux | Detection only | Game/UDP traffic recognized; relay steering was not established. |
| Tibia | Native Linux | Detection only | In-world flows recognized; no redirect was supplied in the recorded test. |
| Other games | Linux / macOS | Untested | Community reports and pull requests are welcome. |

**Arch Linux is the maintainer's verified Linux gameplay platform.** The
[Arch setup guide](arch-linux.md) uses the shared Linux portable installer.
Automated packaging checks are separate from gameplay. The historical release
records describe Ubuntu 22.04 and 24.04 checks for clean Wine/WMI setup,
installed first-run UI, ownership, UID-scoped routing startup, removed/expired
leases, parent-exit cleanup and account-preserving removal. Those CI scenarios
use no official client or account and do not demonstrate login or game routing.

The release record reports the same Linux portable archive passing those checks
on both Ubuntu versions and in Arch userspace in a disposable Docker container. The Arch
container uses an Ubuntu CI host kernel; it is not a native Arch kernel or live
gameplay test. [Portable installer checks](https://github.com/Cheaux/exitlag-bridge/actions/runs/41244802664).

Minecraft, Dota 2 and Tibia results come from earlier native Linux experiments.
Their source reports establish the scope above, not current-version support.
The Minecraft tests carried real relay traffic and then disconnected; detection
or byte counters alone must not be relabelled as working gameplay.

Mac live-game testing used Apple Silicon, macOS 27.2 and Wine 11.17 Staging.
The current Mac adapter recognizes Classic Era and Forever at the standard WoW
installation paths and supports IPv4 TCP only. Linux uses exact executable or
Wine-prefix mappings; UDP/IPv6 experiments do not imply support for every game.

The release remains experimental. Reboot/sleep recovery,
Intel Macs, a second Mac and a complete fresh graphical Linux install/login/game
session remain useful follow-up tests. They are not claimed as completed.

## Evidence stages for a new compatibility report

| Stage | Evidence to record | What it does not establish |
|---|---|---|
| Recognition | exact process/identity or dashboard entry, with the UI panel named | callback delivery or relayed traffic |
| Inspection | attributed game flow and corresponding callback/byte events | a usable redirect decision |
| Decision | returned destination, family and callback contract | successful application to a real packet |
| Application | actual connection/packet path, reverse traffic and relay evidence | stable gameplay or support for another transport/title |
| Gameplay/lifecycle | actual game stage, duration, restarts and cleanup observed | longer soak, another OS/client build or unperformed recovery scenarios |

Report which stages were observed and which were skipped or unavailable. A
synthetic peer can test a bridge mechanism without proving that the vendor
client offers that route. Diagnosis also remains separate from compatibility:
an absent redirect or a disconnect is not enough to assign fault to the vendor
or to exclude a bridge defect.

Use the game-compatibility issue template for new reports. Include the exact game
build, OS/architecture, client/Wine versions, tested stage, observed relay traffic
and cleanup behavior. Remove personal information before attaching diagnostics.
