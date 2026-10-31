# ExitLag on Linux and Mac: setup FAQ

ExitLag Bridge is an unofficial, experimental open-source compatibility project.
It uses the official ExitLag Windows client under Wine and a native routing
backend. [Download installers](https://github.com/Cheaux/exitlag-bridge/releases)
or read the [full installation guide](../installers/README.md).

## Does ExitLag work on Linux?

World of Warcraft Classic Era gameplay has been verified on **Arch Linux** with
the original bridge. Use the [Arch Linux setup guide](arch-linux.md) and shared
portable installer, or the shared `.deb` for Ubuntu 22.04 and 24.04. The packaged
x86_64 Linux app provides graphical setup, exact native
executable or Wine/Proton-prefix mappings, and a privileged nftables/NFQUEUE
backend. Ubuntu 22.04 and 24.04 installer checks pass. Game support depends on the
client's routing callback and the transport; it is not guaranteed for all games.

## Can I use ExitLag on a Mac?

The experimental Mac installer targets Apple Silicon and macOS 15+. Actual live
testing used Apple Silicon and macOS 27.2. WoW Classic Era world gameplay works;
WoW Forever was verified only through a relayed character-selection connection.
Forever world entry was unavailable before release. The current Mac adapter is
WoW-specific, supports IPv4 TCP, and does not implement UDP or IPv6 routing.
No Intel Mac binary is provided. The Mac installers are unsigned and not notarized.

## Is ExitLag Bridge free? Do I still need an ExitLag subscription?

The bridge's own code is free and open source under GPL-3.0-only. You still need
the official ExitLag client and your own valid account and active subscription
or trial. The bridge does not supply accounts or bypass service access checks.
Third-party components retain their existing licenses.

## Where do I get the Windows installer?

Download it yourself from [ExitLag's official page](https://www.exitlag.com/download).
First-run setup opens that page and lets you select the local `.exe`. Complete
the vendor wizard, review its terms, keep `C:\ExitLag`, and uncheck **Launch
ExitLag** at the end. Sign in directly in the official dashboard afterward.
The bridge does not bundle, mirror or automatically download the proprietary client.

## What does the NDIS driver error 0x80004001 mean?

The Windows vendor wizard can report that it could not install the NDIS driver.
For this specific `0x80004001` warning, choose **OK** to continue: native bridge
routing replaces the Windows filtering driver. Other installer failures are
not ignored. Leave ExitLag's redirection method set to **Automatic**; its Windows
NDIS driver is not available on these platforms.

## Do I need to run a routing script in Terminal?

The packaged app starts the bridge and native helper. Open **ExitLag Bridge**,
configure your game if needed, and apply its routes in the official ExitLag
dashboard before making new game connections. The installed Linux helper uses a
graphical polkit prompt. The Mac package installs an administrator helper during
installation. Wine and the official client's account login run as the ordinary user.
The shell commands elsewhere in the repository are for developer setups.

## Can it route native Linux, Wine and Proton games?

Linux supports mappings from a real native executable or a Wine/Proton prefix to
the Windows game identity recognized by ExitLag. Use **Configure games** in the
app. Mapping a prefix covers that entire prefix, so use separate game prefixes.
Detection in the dashboard alone does not prove working relay traffic. Consult
the [tested-games table](compatibility.md) before assuming support.

## Does the bridge connect to ExitLag's relays?

The complete setup does. Our native backend attributes and intercepts recognized
game connections, asks the official client's routing callback for a destination,
and steers traffic into its local proxy. The official client under Wine handles
authentication, route selection and transport through ExitLag's relays. The bridge
does not independently implement the remote route API or relay protocol.

## Is the commercial NetFilter SDK bundled?

No commercial SDK implementation or vendor filtering driver is bundled. The
project supplies its own `nfapi.dll` compatibility implementation and a
presence-only driver stub. Linux nftables/NFQUEUE is separate from the commercial
SDK. The original authoring record for some interface declarations is incomplete;
[THIRD_PARTY.md](../THIRD_PARTY.md) records that provenance limitation.

## Will it lower my ping?

Lower latency is not guaranteed. Geography, the selected relay route, the game
server and the local network affect the result. Compare the same game's latency
measurements on the same server under similar conditions. A lower number in a
different app or at another time is not a controlled comparison.

## How do I uninstall it or report another game?

Quit the bridge first. Use the Mac uninstall package, your Linux package manager,
or the portable archive's uninstall script. Account data is preserved by default;
see the [removal guide](../installers/README.md).

Use the [game compatibility report](https://github.com/Cheaux/exitlag-bridge/issues/new?template=game-compatibility.yml)
for new tests, or submit a pull request. State the game/build, OS/architecture,
launch method and exactly what worked: detection, login, character selection,
gameplay or bidirectional relay traffic. Remove personal details from diagnostics
and do not upload accounts, tokens or Wine prefixes.
