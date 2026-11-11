#!/usr/bin/python3
"""Installed routing supervisor. Runs only immutable installed code as root.
SPDX-License-Identifier: GPL-3.0-only
"""
import argparse
import os
from pathlib import Path
import pwd
import signal
import stat
import subprocess
import time

ROOTS = (Path('/usr/lib/exitlag-bridge'), Path('/usr/local/lib/exitlag-bridge'))


def process_identity(pid):
    base = Path('/proc') / str(pid)
    # The command name may contain spaces and parentheses.
    start = (base / 'stat').read_text().rsplit(')', 1)[1].split()[19]
    return base.stat().st_uid, start


def read_map(path, uid):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError('Game mappings must be private and owned by the game user')
        data = os.read(fd, 65537).decode('utf-8')
    finally:
        os.close(fd)
    count = 0
    identities = set()
    for line in data.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split('\t')
        prefix = parts[0].startswith('wineprefix:')
        if prefix and len(parts) == 2:
            raise ValueError('Wine-prefix mappings require an OWNER_EXE third column; configure the actual Wine/Proton loader')
        if (len(parts) != (3 if prefix else 2) or not parts[1].lower().endswith('.exe')
                or any(c in line for c in '\0\r') or len(line) > 4096):
            raise ValueError('Invalid game mapping')
        source = parts[0].removeprefix('wineprefix:')
        if not source.startswith('/'):
            raise ValueError('Mappings require absolute game paths')
        source_path = Path(source).resolve(strict=True)
        if prefix:
            if not source_path.is_dir() or not parts[2].startswith('/'):
                raise ValueError('A Wine-prefix mapping requires a prefix directory and an absolute loader executable')
            owner = Path(parts[2]).resolve(strict=True)
            executable = owner
        else:
            owner = None
            executable = source_path
        info = executable.stat()
        if not stat.S_ISREG(info.st_mode) or not info.st_mode & 0o111:
            raise ValueError('Map the actual regular executable that owns the game connection')
        key = (source_path, owner)
        if key in identities:
            raise ValueError('Duplicate game mapping')
        identities.add(key)
        count += 1
    if not count or count > 128:
        raise ValueError('Configure between 1 and 128 games before enabling routing')
    return data


def lease_alive(path, uid):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            # Future timestamps (including a backwards wall-clock jump) must
            # not extend an unresponsive launcher's authorization lease.
            age = time.time() - info.st_mtime
            return (stat.S_ISREG(info.st_mode) and info.st_uid == uid and info.st_nlink == 1
                    and not info.st_mode & 0o077 and info.st_size < 64
                    and 0 <= age < 6 and os.read(fd, 64) == b'run\n')
        finally:
            os.close(fd)
    except OSError:
        return False


def parse_args(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--uid', type=int, required=True)
    parser.add_argument('--parent', type=int, required=True)
    parser.add_argument('--map', type=Path, required=True)
    parser.add_argument('--lease', type=Path, required=True)
    parser.add_argument('--udp', action='store_true',
                        help='enable experimental synchronous UDP posts alongside TCP')
    return parser.parse_args(argv)


def runner_command(root, udp=False):
    """Only the fixed runner in the already verified installation is executable."""
    root = Path(root)
    if root not in ROOTS or not isinstance(udp, bool):
        raise ValueError('Use a fixed installed routing mode')
    runner = 'run-udp-multi.sh' if udp else 'run-tcp-redirect.sh'
    return ['/bin/bash', str(root / 'backend' / runner)]


def runner_environment(uid, gid, mapping, log, udp=False):
    """Construct from verified session data, never inherit routing overrides."""
    if not isinstance(udp, bool) or not isinstance(uid, int) or uid < 1000 or not isinstance(gid, int) or gid < 0:
        raise ValueError('Invalid authorized routing user or mode')
    env = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', LANG='C.UTF-8', HOME='/root',
               SUDO_UID=str(uid), SUDO_GID=str(gid), EXL_USER_UID=str(uid),
               TEST_DEST='any', ENABLE_REDIRECT='1', EXITLAG_IDENTITY_MAP=str(mapping),
               NETD_LOG=str(log))
    if udp:
        env.update(UDP_TEST_DEST='any', ENABLE_UDP_OBSERVE='1',
                   ENABLE_UDP_STEER='1', ENABLE_UDP_MULTI='1')
    return env


def main():
    args = parse_args()
    root = Path(__file__).resolve().parents[2]
    if os.geteuid() != 0 or root not in ROOTS:
        raise SystemExit('Use the installed ExitLag Bridge launcher')
    for directory in (root, *root.parents):
        info = directory.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit('The installed program directory is not protected')
    authorized = os.environ.get('PKEXEC_UID', os.environ.get('SUDO_UID', ''))
    if str(args.uid) != authorized or args.uid < 1000:
        raise SystemExit('Routing authorization does not match the game user')
    user = pwd.getpwuid(args.uid)
    identity = process_identity(args.parent)
    if identity[0] != args.uid:
        raise SystemExit('The launcher does not belong to the authorized user')
    data = read_map(args.map, args.uid)
    if not lease_alive(args.lease, args.uid):
        raise SystemExit('The launcher session has ended')
    directory = Path('/run/exitlag-bridge-' + str(args.uid))
    if directory.is_symlink():
        raise SystemExit('Unexpected runtime directory')
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise SystemExit('Unexpected runtime ownership')
    mapping = directory / 'games.map'
    fd = os.open(mapping, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        output.write(data)
    env = runner_environment(args.uid, user.pw_gid, mapping, directory / 'backend.log', args.udp)
    stop = False
    def stopping(*_):
        nonlocal stop
        stop = True
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, stopping)
    child = subprocess.Popen(runner_command(root, args.udp), env=env, cwd='/', start_new_session=True)
    try:
        while not stop and child.poll() is None and lease_alive(args.lease, args.uid):
            try:
                if process_identity(args.parent) != identity:
                    break
            except (FileNotFoundError, ProcessLookupError):
                break
            time.sleep(.5)
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        mapping.unlink(missing_ok=True)
    if not stop and child.returncode not in (0, -signal.SIGTERM, 143):
        raise SystemExit(child.returncode or 1)


if __name__ == '__main__':
    main()
