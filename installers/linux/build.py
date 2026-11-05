#!/usr/bin/env python3
"""Build x86_64 Linux packages; --portable-only also works without Debian tools.
SPDX-License-Identifier: GPL-3.0-only
"""
import argparse
import hashlib
import json
import os
import platform
import re
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[2]
VERSION = '0.4.0+arch.1'
FILES = ('backend/exitlag-netd', 'backend/run-tcp-redirect.sh', 'backend/run-udp-multi.sh', 'backend/runtime-guard.sh',
         'backend/nft-setup.sh', 'backend/nft-teardown.sh', 'installers/linux/app.py',
         'installers/linux/run_root.py', 'installers/linux/game_picker.py',
         'installers/linux/desktop_support.py', 'installers/linux/desktop_session.py',
         'installers/linux/desktop_ui.py',
         'tools/discover-game-processes.py', 'installers/setup.py', 'LICENSE', 'THIRD_PARTY.md',
         'docs/provenance-review.md')


PAYLOADS = ('nfapi.dll', 'nfextlag.sys', 'wbemprox.dll')


def payload_manifest():
    directory = ROOT / 'installers/payloads'
    manifest = json.loads((directory / 'manifest.json').read_text())
    for name in PAYLOADS:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing regular Linux payload: ' + name)
        if manifest.get('files', {}).get(name) != hashlib.sha256(path.read_bytes()).hexdigest():
            raise ValueError('Payload checksum mismatch: ' + name)
    return manifest


def populate(target, source_revision=None):
    manifest = payload_manifest()
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0o755)
    for name in FILES:
        destination = target / name; destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, destination)
    for name in ('installers/bridge_setup', 'LICENSES'):
        shutil.copytree(ROOT / name, target / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
    payloads = target / 'installers/payloads'
    payloads.mkdir(parents=True)
    for name in PAYLOADS:
        shutil.copy2(ROOT / 'installers/payloads' / name, payloads / name)
    manifest['files'] = {name: manifest['files'][name] for name in PAYLOADS}
    (payloads / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')
    (target / '.exitlag-bridge-program').write_text(VERSION + '\n')
    shutil.copy2(ROOT / 'macos/app/BridgeIcon.svg', target / 'icon.svg')
    hashes = {str(path.relative_to(target)): hashlib.sha256(path.read_bytes()).hexdigest()
              for path in sorted(target.rglob('*')) if path.is_file() and not path.is_symlink()}
    (target / 'build-info.json').write_text(json.dumps({
        'version': VERSION, 'target': 'arch-linux-x86_64',
        'source_revision': source_revision, 'files': hashes,
        'live_exitlag_verified': False,
    }, indent=2, sort_keys=True) + '\n')
    for path in target.rglob('*'):
        if path.is_symlink(): raise ValueError('Do not package symlinks in the Linux program tree')
        path.chmod(0o755 if path.is_dir() or path.suffix == '.sh' or path.name == 'exitlag-netd' else 0o644)


def desktop(prefix):
    return f'''[Desktop Entry]
Type=Application
Name=ExitLag Bridge
Comment=Unofficial ExitLag compatibility launcher
Exec=/usr/bin/python3 -I {prefix}/installers/linux/app.py
Icon={prefix}/icon.svg
Terminal=false
Categories=Game;Network;
Actions=Games;Quit;

[Desktop Action Games]
Name=Configure games
Exec=/usr/bin/python3 -I {prefix}/installers/linux/app.py --manage-games

[Desktop Action Quit]
Name=Quit ExitLag Bridge
Exec=/usr/bin/python3 -I {prefix}/installers/linux/app.py --quit
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-revision', help='40-character Git commit of the source being packaged')
    parser.add_argument('--portable-only', action='store_true',
                        help='build the x86_64 portable installer without Debian tools')
    args = parser.parse_args()
    if args.source_revision and not re.fullmatch(r'[0-9a-f]{40}', args.source_revision):
        parser.error('--source-revision must be a complete lowercase Git commit')
    if not sys.platform.startswith('linux'):
        parser.error('Build Linux packages on Linux')
    if platform.machine().lower() not in ('x86_64', 'amd64'):
        parser.error('The Linux beta supports x86_64 only')
    if not args.portable_only:
        arch = subprocess.check_output(['dpkg', '--print-architecture'], text=True).strip()
        if arch != 'amd64': parser.error('The Linux beta supports amd64')
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=True)
    staging = ROOT / 'build/linux-package'
    shutil.rmtree(staging, ignore_errors=True); staging.mkdir(parents=True)
    if not args.portable_only:
        deb = staging / 'deb'
        populate(deb / 'usr/lib/exitlag-bridge', args.source_revision)
        applications = deb / 'usr/share/applications'; applications.mkdir(parents=True)
        (applications / 'exitlag-bridge.desktop').write_text(desktop('/usr/lib/exitlag-bridge'))
        control = deb / 'DEBIAN'; control.mkdir()
        # Build callers can use a private umask. These published system paths
        # must still be traversable by the ordinary desktop user after install.
        for directory in (deb, deb / 'usr', deb / 'usr/lib', deb / 'usr/share', applications, control):
            directory.chmod(0o755)
        (applications / 'exitlag-bridge.desktop').chmod(0o644)
        (control / 'control').write_text(f'''Package: exitlag-bridge
Version: {VERSION}
Architecture: amd64
Maintainer: ExitLag Bridge contributors
Section: games
Priority: optional
Depends: python3 (>= 3.10), python3-tk, nftables, libmnl0, policykit-1, curl, ca-certificates, libfreetype6, libx11-6, libxext6, libxrender1, libxrandr2, libxcursor1, libxi6, libxinerama1, libxxf86vm1, libgl1, libvulkan1, fontconfig, libdbus-1-3, libudev1, libasound2 | libasound2t64, libgnutls30 | libgnutls30t64
Description: Unofficial ExitLag compatibility bridge
 Requires a separately downloaded official ExitLag installer and account.
 The proprietary client and account data are not included.
''')
        (control / 'prerm').write_text('''#!/bin/sh
set -eu
if pgrep -f '/usr/lib/exitlag-bridge/installers/linux/(app|run_root).py' >/dev/null; then
  echo 'Quit ExitLag Bridge before removing or upgrading it.' >&2
  exit 1
fi
exit 0
''')
        (control / 'prerm').chmod(0o755)
        subprocess.run(['dpkg-deb', '--root-owner-group', '--build', str(deb), str(output / f'exitlag-bridge_{VERSION}_amd64.deb')], check=True)
    portable = staging / f'exitlag-bridge-{VERSION}-linux-x86_64'; portable.mkdir()
    portable.chmod(0o755)
    populate(portable / 'program', args.source_revision)
    shutil.copy2(ROOT / 'installers/linux/install.sh', portable / 'install.sh')
    shutil.copy2(ROOT / 'installers/linux/uninstall.sh', portable / 'uninstall.sh')
    (portable / 'install.sh').chmod(0o755)
    (portable / 'uninstall.sh').chmod(0o755)
    (portable / 'exitlag-bridge.desktop').write_text(desktop('/usr/local/lib/exitlag-bridge'))
    (portable / 'exitlag-bridge.desktop').chmod(0o644)
    with tarfile.open(output / f'exitlag-bridge-{VERSION}-linux-x86_64.tar.gz', 'w:gz') as tar:
        def normalize(item):
            item.uid = item.gid = 0; item.uname = item.gname = 'root'; item.mtime = 0
            return item
        tar.add(portable, arcname=portable.name, filter=normalize)
    hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file() and p.suffix != '.json'}
    (output / 'SHA256SUMS.json').write_text(json.dumps(hashes, indent=2) + '\n')
    print(json.dumps(dict(packages_built=True, proprietary_client_included=False)))


if __name__ == '__main__': main()
