# One Linux installer for Arch and Ubuntu

[Download the Linux x86_64 installer](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/exitlag-bridge-0.4.0-alpha.2-linux-x86_64.tar.gz).
The same archive and `install.sh` are used on Arch Linux, Ubuntu 22.04 and Ubuntu
24.04. Dependencies come from your distribution's package manager.

Already using the Ubuntu `.deb`? You can keep that installation. Before switching
to the shared installer, quit the bridge and remove the `.deb` with your package
manager (`sudo apt remove exitlag-bridge`). Account data is preserved. Use one
installation method at a time.

## 1. Install dependencies for your distribution

### Ubuntu 22.04 or 24.04

```sh
sudo apt-get update
bridge_audio_package=libasound2
bridge_tls_package=libgnutls30
if apt-cache show libasound2t64 >/dev/null 2>&1; then bridge_audio_package=libasound2t64; fi
if apt-cache show libgnutls30t64 >/dev/null 2>&1; then bridge_tls_package=libgnutls30t64; fi
sudo apt-get install python3 python3-tk nftables libmnl0 policykit-1 curl ca-certificates \
  libfreetype6 "$bridge_audio_package" "$bridge_tls_package" libx11-6 libxext6 \
  libxrender1 libxrandr2 libxcursor1 libxi6 libxinerama1 libxxf86vm1 libgl1 \
  libvulkan1 fontconfig fonts-liberation libdbus-1-3 libudev1
```

### Arch Linux

```sh
sudo pacman -Syu --needed python tk xz nftables libmnl polkit curl ca-certificates \
  freetype2 libx11 libxext libxrender libxrandr libxcursor libxi libxinerama \
  libxxf86vm libglvnd vulkan-icd-loader fontconfig dbus systemd-libs \
  alsa-lib gnutls ttf-liberation
```

A Wayland desktop also needs XWayland (`xwayland` on Ubuntu, `xorg-xwayland` on
Arch). Your desktop must run a polkit authentication agent for the routing prompt.
Use your normal graphics drivers. Setup downloads its own pinned Wine runtime.

## 2. Install the same archive on either distribution

From the directory containing the downloaded archive:

```sh
tar -xzf exitlag-bridge-0.4.0-alpha.2-linux-x86_64.tar.gz
cd exitlag-bridge-0.4.0-linux-x86_64
sudo bash ./install.sh
```

Open **ExitLag Bridge** from the applications menu as your normal desktop user.
It installs under `/usr/local/lib/exitlag-bridge`.

## 3. Choose the official Windows .exe in the app

The bridge's first-run window has two buttons:

1. **Download from ExitLag** opens the official download page in your browser.
   Download the Windows installer yourself.
2. **Choose installer…** opens a file picker filtered to `.exe` files. Select the
   file you downloaded, usually from your Downloads folder.

The app checks the file, prepares Wine, then runs the official Windows installer
wizard. Review its terms, keep `C:\ExitLag`, and uncheck **Launch ExitLag** at the
end. The specific NDIS warning `0x80004001` can be acknowledged because native
routing replaces that Windows driver; other failures stop setup.

Use **Configure games…**, then **Launch ExitLag**. Authorize routing in your
desktop's polkit prompt. Sign in directly in the official dashboard with your
own account and active subscription or trial, select the game and apply its route
before making a new game connection. No developer routing script is needed.

## Removal and evidence

Quit the bridge, then run `sudo bash ./uninstall.sh` from the extracted archive.
Settings, the private Wine prefix and account data are preserved.

The exact same archive passes install, first-run UI, fresh Wine/WMI, native
routing cleanup and account-preserving removal checks on Ubuntu 22.04/24.04 and
Arch userspace in a disposable Docker container. The Arch container uses the
Ubuntu CI host's kernel; it is not a native Arch kernel or real-game test.
[Shared installer checks](https://github.com/Cheaux/exitlag-bridge/actions/runs/41244802664).

Real WoW Classic Era gameplay was separately verified by the maintainer on Arch
Linux. A complete fresh vendor-install/login/gameplay cycle has not been repeated
with the packaged installer. Other distributions need their own reports.
See the [full compatibility record](compatibility.md).
