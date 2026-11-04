# Install ExitLag Bridge

[Choose your platform's download](https://cheaux.github.io/exitlag-bridge/#downloads).
Choose **Mac** or **Linux**. The shared Linux archive works on Arch and Ubuntu;
the optional Ubuntu `.deb` is listed under advanced downloads.

The bridge is GPL-3.0-only. ExitLag is downloaded separately from
[its official download page](https://www.exitlag.com/download). We do not ship,
mirror, automatically download, or silently accept terms for its Windows client.

Both desktop setup windows have a **Download from ExitLag** button that opens
the official page and a **Choose installer…** button that opens a `.exe` file
picker. After selecting your download, setup prepares a private Wine runtime and
runs the vendor wizard interactively. Review its terms,
use the proposed `C:\ExitLag` destination, and leave **Launch ExitLag** unchecked.
Setup stops on vendor failure, missing files, or an unsupported `nfapi` interface.
Sign in directly in the official client after setup completes.
The vendor wizard may warn that the Windows NDIS driver could not install
(`0x80004001`). Choose **OK** to continue this specific warning: native bridge
routing replaces the Windows driver. Other installer failures are not ignored.

## macOS

Download and install the [Mac installer](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/ExitLag-Bridge-0.4.0-alpha.2-macos-arm64.pkg), then open **ExitLag Bridge** in Applications.
First run shows setup; subsequent launches open the real ExitLag dashboard.
The package includes an immutable standalone Python interpreter for the routing
helper, so end users do not need Command Line Tools or Homebrew. Wine downloads
and the vendor wizard run as the ordinary user. Apple Silicon also needs Rosetta;
install it through Apple's own system prompt and review Apple's terms yourself.

The downloadable Mac beta is arm64 for Apple Silicon. It supports one installation user, macOS 15+, and the standard
`/Applications/World of Warcraft` paths for Classic Era and Forever. Current
live-game evidence is Apple Silicon/macOS 27.2. Intel builds, reboot/sleep
recovery, and Forever world entry still need validation. Forever has only been
verified through character selection.

The [Mac uninstall package](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/ExitLag-Bridge-Uninstall-0.4.0-alpha.2-macos-arm64.pkg) removes the program and administrator helper,
after quitting the bridge. It preserves the private Wine prefix and account data.
The app has an ad-hoc signature. The `.pkg` installers are unsigned, and the
build is not notarized. Do not disable system-wide security settings to install it.

Build with Xcode Command Line Tools, Python 3.10+ and standard build tools:

```sh
python3 installers/build_runtime.py payloads --output installers/payloads
bash macos/app/build.sh
```

The builder pins and verifies Wine, Python and Zig downloads. Generated artifacts
are ignored by Git. The builder's own Python version may need the standard
`xz` support for tar archives; installed users do not build components.

## Linux

The shared installer supports **x86_64**. Download the
[Linux archive](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/exitlag-bridge-0.4.0-alpha.2-linux-x86_64.tar.gz)
and follow the [same Linux setup guide](../docs/linux.md) on Arch Linux or Ubuntu
22.04/24.04. It installs under `/usr/local/lib/exitlag-bridge`; system dependencies
use `apt` on Ubuntu or `pacman` on Arch. **Arch Linux** is the maintainer's
verified WoW gameplay platform.

The exact archive passed installation, first-run UI, fresh Wine/WMI, helper
cleanup and removal checks on both Ubuntu versions and in Arch userspace in a
disposable Docker container. The container uses the CI host's Ubuntu kernel;
actual Arch gameplay evidence comes from the maintainer's separate test.
[Shared Linux installer verification](https://github.com/Cheaux/exitlag-bridge/actions/runs/41244802664).

### Optional Ubuntu package

For Ubuntu 22.04 and 24.04, download the **same [Ubuntu package](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/exitlag-bridge_0.4.0_amd64.deb)**,
then install it with your graphical package manager or run:

```sh
sudo apt install ./exitlag-bridge_0.4.0_amd64.deb
```

This is the Ubuntu 22.04 build, verified unchanged on both Ubuntu versions for
installation, first-run UI, fresh Wine/WMI, native routing cleanup and
account-preserving removal. See the
[shared package check](https://github.com/Cheaux/exitlag-bridge/actions/workflows/ubuntu-package-compatibility.yml).
This installs desktop integration and declares system runtime dependencies.
Open **ExitLag Bridge** from the applications menu as your normal user.

Choose one installation method. Remove a `.deb` installation with your package
manager before switching to the shared portable installer; account data is
preserved. The shared portable archive contains its own `uninstall.sh`.

### Launch and removal

The development branch provides a [running-game picker](../docs/game-selection.md)
under Configure games. For Wine/Proton it captures prefix/runtime and offers
actual PE images, removing normal manual Linux-path entry. The upstream release
downloads above predate this interface. Advanced mappings remain available.

Use **Configure games** to select the actual native executable or the game's
Wine/Proton prefix and enter the Windows executable identity recognized by
ExitLag. A prefix mapping additionally requires selecting the actual Wine/Proton
loader executable that owns the game socket, rather than a launcher script.
Existing two-column prefix mappings must be updated: the third Tab-separated
column is the absolute loader executable path. Native executable mappings keep
their two-column format. Paths must exist and executables must be regular files
with execute permission; duplicate canonical mappings are rejected.

A prefix mapping authorizes the selected loader in the entire prefix, so
separate game prefixes are preferable. This is an explicit allowlist, not proof
of the Windows executable running inside that prefix. Unmapped processes retain
their normal identity. Apply the game in ExitLag's dashboard before establishing
new game connections. See [process identity translation](../docs/process-identity-translation.md)
for the mapping format and its trust boundary.

Launching routing uses a graphical polkit administrator prompt. The installed
root-owned supervisor only runs the installed backend, snapshots data-only game
mappings, scopes nftables rules to the authorized UID, and stops when the launcher
exits or its six-second lease expires. Wine and login always run unprivileged.
Quitting the bridge restores its firewall surface; reconnect existing games.

Removing either package preserves data under the user's XDG data directory.
The shared setup CLI can remove downloaded components or explicitly purge a
managed prefix, with a separate purge confirmation. It refuses unrelated,
unmarked directories. Legacy developer setups are preserved rather than
silently migrated.

Build on Ubuntu/Debian with the dependencies in the validation workflow:

```sh
make -C backend
python3 installers/build_runtime.py payloads --output installers/payloads
python3 installers/linux/build.py --output build/releases
```

On Arch Linux x86_64, the installed LLVM toolchain can build all required Linux
payloads without downloading Zig:

```sh
sudo pacman -S --needed base-devel clang lld llvm bison flex m4 git
make -C backend
python3 installers/build_runtime.py payloads --toolchain llvm --arch x86_64 --output installers/payloads
python3 installers/linux/build.py --portable-only --source-revision "$(git rev-parse HEAD)" --output build/releases
cp build/installer/exitlag-bridge-wine-source.tar.gz build/releases/
```

Use a reviewed, committed tree for release builds. The `--source-revision` value
is recorded in `program/build-info.json` with hashes for packaged program files;
if omitted the revision is explicitly unknown (`null`). The Linux packaged shim preserves the core exports plus the two existing
driver-management exports with explicit unsupported status; its normal `DllMain`
entrypoint does not enable the macOS timer workaround. The exact combined export
set is checked during payload construction. The builder verifies
required payload hashes before staging and includes only the three Linux payloads.
Unrelated files in `installers/payloads` are excluded. LLVM tool changes invalidate
the cached Wine configuration; the legacy default Zig path is preserved.

`--portable-only` produces the portable installer without `dpkg` or a Debian package. The
builder does not download or include the proprietary ExitLag client. An absent
`installers/payloads` directory must be built first; a source archive alone is
not an installable runtime package.

## Verification and distribution

`tests/test_installer.py` checks download verification, archive extraction,
private ownership, interrupted setup, interactive vendor handoff and removal.
`tests/installer_fresh_runtime.py` boots the actual pinned Wine distribution in a
fresh temporary prefix and verifies the patched WMI class, repeat setup and
preserved data. No real account or proprietary executable is used in CI.
Desktop/supervisor checks are in `tests/test_linux_desktop.py` and
`tests/test_linux_launcher.py`. The latter runs without opening a Tk window and
covers Windows-console encodings, uncertain process queries and cleanup after a
Wine timeout. Routing leases accept timestamps only within the previous six
seconds; a backwards wall-clock jump stops the session until it is restarted.

Installer checks do not prove routing for every game. Reports must distinguish
world gameplay, character selection, synthetic tests and untested games. Submit
compatibility reports using the issue template; redact account information and
local paths. Do not upload prefixes or raw Wine logs.

Release assets must include the matching GPL bridge source and the generated
`exitlag-bridge-wine-source.tar.gz` corresponding to the patched Wine DLL.
Runtime licenses retain their upstream terms; see `THIRD_PARTY.md` and `LICENSES`.
This repository starts from a source-only snapshot. Runtime data, prior local
histories, build caches and settings are excluded. `tools/audit-source.py` checks
committed source and reachable author/committer emails before release. It detects
specific privacy hazards and does not provide legal or security clearance.
