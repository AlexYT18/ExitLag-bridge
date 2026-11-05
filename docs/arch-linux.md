# ExitLag Bridge on Arch Linux

The `arch-linux-hardening` development branch adds a
[running-game process picker](game-selection.md). The upstream release archive
linked below predates that interface. Updating a source checkout does not update
an already installed program; build/install the updated program separately.
This branch also adds a minimal game dashboard and an explicit, default-off
experimental UDP toggle. [UDP scope and validation](udp-multi.md) describes its
synthetic IPv4/IPv6 evidence and limits. The older upstream download below lacks
these changes. Build the current portable program using the procedure below;
a build alone does not establish live ExitLag or game compatibility.

**WoW Classic Era gameplay has been verified by the maintainer on Arch Linux.**
Use the same Linux x86_64 installer as Ubuntu 22.04 and 24.04.
[Common Linux installation guide](linux.md).

[Download for Arch Linux](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/exitlag-bridge-0.4.0-alpha.2-linux-x86_64.tar.gz)
· [All platform downloads](https://cheaux.github.io/exitlag-bridge/#downloads)

## Build the current development installer

On Arch x86_64, install build tools in addition to the runtime dependencies below:

```sh
sudo pacman -S --needed base-devel clang lld llvm bison flex m4 git
make -C backend
python3 installers/build_runtime.py payloads --toolchain llvm --arch x86_64 --output installers/payloads
python3 installers/linux/build.py --portable-only --source-revision "$(git rev-parse HEAD)" --output build/releases
cp build/installer/exitlag-bridge-wine-source.tar.gz build/releases/
```

Build from a reviewed, committed source tree so the recorded revision identifies
its actual sources. The LLVM path uses installed tools and downloads checksum-pinned
Wine sources; it does not download Zig or package a synthetic game companion.
The default Zig path remains available for existing build callers. Changing LLVM
binaries invalidates the cached Wine configuration and PE objects.

The native core shim retains its 18 exports. The packaged shim also preserves
the two existing driver-management exports, which explicitly return unsupported;
the Linux package uses the normal `DllMain` entrypoint and does not enable the
macOS timer workaround. The builder checks the exact combined export-name set.

The portable program includes the native helper, current dashboard, and real
`nfapi.dll`, `nfextlag.sys`, and patched `wbemprox.dll` builds. Packaging verifies
payload hashes and writes `program/build-info.json` with the requested source
revision and individual program file hashes. It excludes unrelated payload files,
account state and the proprietary installer. This manifest is integrity metadata,
not a signature or proof of gameplay. Publish the matching bridge sources and the
corresponding Wine source archive alongside the binary package.

Extract `build/releases/exitlag-bridge-0.4.0+arch.2-linux-x86_64.tar.gz`, then run its
`install.sh` as described below. Updating Git sources alone does not update
`/usr/local/lib/exitlag-bridge`. Quit the running bridge before installing an update;
the installer preserves the separate user setup directory.

## 1. Install dependencies

On an updated Arch x86_64 desktop:

```sh
sudo pacman -Syu --needed python tk xz nftables libmnl polkit curl ca-certificates \
  freetype2 libx11 libxext libxrender libxrandr libxcursor libxi libxinerama \
  libxxf86vm libglvnd vulkan-icd-loader fontconfig dbus systemd-libs \
  alsa-lib gnutls ttf-liberation
```

Wayland sessions also need `xorg-xwayland`. Your desktop must have a running
polkit authentication agent so the routing authorization prompt can appear.
Use your normal graphics drivers. Setup downloads its own pinned Wine runtime;
a separate system Wine installation is not required for the packaged app.

## 2. Extract and install

In the directory containing the downloaded archive:

```sh
tar -xzf exitlag-bridge-0.4.0-alpha.2-linux-x86_64.tar.gz
cd exitlag-bridge-0.4.0-linux-x86_64
sudo bash ./install.sh
```

The program installs under `/usr/local/lib/exitlag-bridge` and adds an application
menu entry. Open **ExitLag Bridge** as your ordinary desktop user.

## 3. Complete ExitLag setup

Click **Download from ExitLag** in the app to open the official page, then
**Choose installer…** to select the downloaded Windows `.exe` in a file picker.
Review the vendor terms and complete its
wizard with `C:\ExitLag` as the destination. Leave **Launch ExitLag** unchecked.

The specific NDIS driver warning `0x80004001` can be acknowledged with **OK**:
native routing replaces that Windows driver. Other installer errors are not ignored.
Sign in directly in the official ExitLag dashboard using your own account and
active subscription or trial.

Use **Configure games** to map the native game executable or its Wine/Proton
prefix to the Windows identity recognized by ExitLag. Apply the route in the
official dashboard before making a new game connection. The packaged app starts
the helper through polkit; no developer routing script is needed.

## Removal and tested scope

Quit ExitLag Bridge, then run `sudo bash ./uninstall.sh` from the extracted
archive. Account data is preserved by default.

The original Arch bridge was tested with real WoW Classic Era gameplay. The
shared portable binary is built on the Ubuntu 22.04 compatibility baseline;
automated packaged-installer checks now also pass in Arch userspace in a
disposable container using the Ubuntu CI host kernel. A fresh vendor-install,
login and gameplay cycle on Arch has not been repeated. These are
different checks, and the Arch gameplay result remains recorded as working.
See the [full compatibility record](compatibility.md) for other games.
