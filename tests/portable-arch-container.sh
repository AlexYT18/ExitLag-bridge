#!/bin/bash
# Test-only: run in the disposable Arch container from the compatibility workflow.
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail
[[ $EUID == 0 && -f /.dockerenv && ${EXITLAG_PORTABLE_CI:-} == 1 ]] || {
  echo 'This test requires its disposable CI container.' >&2; exit 1;
}
pacman-key --init
pacman-key --populate archlinux
pacman -Syu --noconfirm --needed python tk xz nftables libmnl polkit curl ca-certificates \
  freetype2 libx11 libxext libxrender libxrandr libxcursor libxi libxinerama \
  libxxf86vm libglvnd vulkan-icd-loader fontconfig dbus systemd-libs \
  alsa-lib gnutls ttf-liberation xorg-server-xvfb xorg-xauth sudo procps-ng
pacman -Q glibc python nftables libmnl
useradd --create-home --uid 1001 --shell /bin/bash bridge-test
echo 'bridge-test ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/exitlag-ci
chmod 440 /etc/sudoers.d/exitlag-ci
echo 'f53ad08c2e1283861df1fa8f76af07d76053c089771b9ce05904fc6673b57969  /workspace/build/shared-linux/installer.tar.gz' | sha256sum --check -
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
tar -xzf /workspace/build/shared-linux/installer.tar.gz -C "$work"
payload="$work/exitlag-bridge-0.4.0-linux-x86_64"
bash "$payload/install.sh"
ldd /usr/local/lib/exitlag-bridge/backend/exitlag-netd
runuser -u bridge-test -- xvfb-run -a /usr/bin/python3 /workspace/tests/test_desktop_ui.py /usr/local/lib/exitlag-bridge
runuser -u bridge-test -- xvfb-run -a /usr/bin/python3 /workspace/tests/installer_fresh_runtime.py /usr/local/lib/exitlag-bridge/installers/payloads
unshare --net runuser -u bridge-test -- /usr/bin/python3 /workspace/tests/test_installed_routing.py /usr/local/lib/exitlag-bridge
runuser -u bridge-test -- /usr/bin/python3 -c 'from pathlib import Path; p=Path.home()/".local/share/exitlag-bridge/portable-test-marker"; p.parent.mkdir(parents=True,exist_ok=True); p.touch()'
bash "$payload/uninstall.sh"
runuser -u bridge-test -- /usr/bin/python3 -c 'from pathlib import Path; assert (Path.home()/".local/share/exitlag-bridge/portable-test-marker").is_file()'
test ! -e /usr/local/lib/exitlag-bridge
echo 'Arch container: same portable archive passed install, UI, Wine/WMI, routing cleanup and account-preserving removal.'
