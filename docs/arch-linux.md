# ExitLag Bridge on Arch Linux

**WoW Classic Era gameplay has been verified by the maintainer on Arch Linux.**
Use the same Linux x86_64 installer as Ubuntu 22.04 and 24.04.
[Common Linux installation guide](linux.md).

[Download for Arch Linux](https://github.com/Cheaux/exitlag-bridge/releases/download/v0.4.0-alpha.2/exitlag-bridge-0.4.0-alpha.2-linux-x86_64.tar.gz)
· [All platform downloads](https://cheaux.github.io/exitlag-bridge/#downloads)

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
