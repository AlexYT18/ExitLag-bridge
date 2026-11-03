"""Unprivileged, generation-checked candidates for the Linux process picker.

Names and Steam environment values are display hints. Authorization is an
explicit selection of a verified socket-owning executable (and, for Wine, its
observed prefix). A mapped PE file is a path candidate, not ExitLag catalogue
verification or attestation of a Windows process inside a shared prefix.
SPDX-License-Identifier: GPL-3.0-only
"""
import importlib.util
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import struct
from dataclasses import dataclass, replace

MAX_FILE = 4 * 1024 * 1024
MAX_ENV = 1024 * 1024
MAX_PROCESSES = 8192
MAX_FDS = 8192
MAX_IMAGES = 128
_FIELDS = ('WINEPREFIX', 'STEAM_COMPAT_DATA_PATH', 'SteamAppId', 'STEAM_COMPAT_APP_ID')
_SOCKET = re.compile(r'socket:\[([1-9][0-9]*)\]\Z')
_DRIVE = re.compile(r'([A-Za-z]):\Z')


class PickerError(ValueError):
    """A candidate is unavailable, ambiguous, stale, or outside the safe bounds."""


@dataclass(frozen=True)
class Candidate:
    pid: int
    uid: int
    start_time: int
    name: str
    kind: str
    executable: Path
    prefix: Path | None
    transports: tuple[str, ...]
    socket_count: int
    inodes: tuple[int, ...]
    steam_appid: str | None = None
    executable_device: int = 0
    executable_inode: int = 0
    prefix_device: int | None = None
    prefix_inode: int | None = None


@dataclass(frozen=True)
class ImageCandidate:
    path: Path
    windows_path: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int
    observed: bool = False


def _field(value):
    if not value or any(ord(c) < 32 or ord(c) == 127 for c in str(value)):
        raise PickerError('Paths and identities must be nonempty single-line values')
    if len(str(value).encode('utf-8')) > 4095:
        raise PickerError('Path exceeds the supported length')
    return str(value)


def _read_fd(fd, limit):
    result = bytearray()
    while len(result) <= limit:
        part = os.read(fd, min(65536, limit + 1 - len(result)))
        if not part:
            return bytes(result)
        result.extend(part)
    raise PickerError('Process information exceeds the safe read limit')


def _read_at(directory, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW,
                 dir_fd=directory)
    try:
        return _read_fd(fd, limit)
    finally:
        os.close(fd)


def _read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        return _read_fd(fd, limit)
    finally:
        os.close(fd)


def _canonical(path, directory=False, executable=False):
    path = Path(_field(path))
    if not path.is_absolute():
        raise PickerError('An absolute path is required')
    try:
        path = path.resolve(strict=True)
    except RuntimeError:
        raise PickerError('Selected path contains an unresolvable symbolic link') from None
    _field(path)
    info = path.stat()
    if directory:
        valid = stat.S_ISDIR(info.st_mode)
    else:
        valid = stat.S_ISREG(info.st_mode) and (not executable or info.st_mode & 0o111)
    if not valid:
        raise PickerError('Selected path is not a usable directory or executable')
    return path, info


def _birth(data, pid):
    try:
        first, _comm, rest = data.partition(b'(')
        if int(first.strip()) != pid or not rest:
            raise ValueError
        fields = rest.rsplit(b')', 1)[1].split()
        value = fields[19]
        if not value.isdigit() or not 0 < int(value) < 2**64:
            raise ValueError
        return int(value)
    except (ValueError, IndexError):
        raise PickerError('Malformed process generation') from None


def _uids(data):
    rows = [line.split()[1:] for line in data.splitlines() if line.startswith(b'Uid:')]
    if len(rows) != 1 or len(rows[0]) != 4 or not all(v.isdigit() for v in rows[0]):
        raise PickerError('Malformed process ownership')
    return tuple(int(v) for v in rows[0])


def _environment(data):
    result = {}
    for entry in data.split(b'\0'):
        key, sep, value = entry.partition(b'=')
        if not sep:
            continue
        name = key.decode('ascii', errors='replace')
        if name not in _FIELDS:
            continue
        text = value.decode('utf-8', errors='strict')
        if name in result and result[name] != text:
            raise PickerError('Conflicting process prefix metadata')
        result[name] = text
    return result


def _identity_key(candidate):
    return (candidate.pid, candidate.uid, candidate.start_time, candidate.executable,
            candidate.executable_device, candidate.executable_inode, candidate.prefix,
            candidate.prefix_device, candidate.prefix_inode, candidate.kind)


class ProcessPicker:
    def __init__(self, discovery_path, proc_root=Path('/proc'), uid=None):
        self.proc_root = Path(proc_root)
        self.uid = os.getuid() if uid is None else uid
        specification = importlib.util.spec_from_file_location(
            '_exitlag_picker_discovery_' + str(id(self)), discovery_path)
        if specification is None or specification.loader is None:
            raise PickerError('Process discovery component is unavailable')
        self.discovery = importlib.util.module_from_spec(specification)
        try:
            specification.loader.exec_module(self.discovery)
        except (OSError, ImportError):
            raise PickerError('Process discovery component is unavailable') from None

    def _network(self):
        result, readable = {}, 0
        for name, proto, v6 in (('tcp', 'tcp', False), ('tcp6', 'tcp', True),
                                ('udp', 'udp', False), ('udp6', 'udp', True)):
            try:
                data = _read_file(self.proc_root / 'net' / name, MAX_FILE)
            except FileNotFoundError:
                continue
            readable += 1
            for line in data.decode('ascii', errors='strict').splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10 or not fields[9].isdigit():
                    continue
                inode = int(fields[9])
                if not 0 < inode < 2**64:
                    continue
                try:
                    # Use the CLI's family-aware address interpretation; unlike
                    # display hints, inode + held fd is the ownership evidence.
                    local = self.discovery.fmt_addr(fields[1], v6)
                    remote = self.discovery.fmt_addr(fields[2], v6)
                    for value in (fields[1], fields[2]):
                        address, port = value.split(':')
                        if (len(address) != (32 if v6 else 8) or len(port) != 4 or
                                any(c not in '0123456789abcdefABCDEF' for c in address + port)):
                            raise ValueError
                except (ValueError, IndexError, OSError):
                    continue
                endpoint = (proto, local, remote)
                if inode in result and result[inode] != endpoint:
                    raise PickerError('Conflicting kernel socket records; refresh the process list')
                result[inode] = endpoint
        if not readable:
            raise PickerError('Kernel socket tables are unavailable')
        return result

    def _identity(self, fd, pid):
        owner = os.fstat(fd).st_uid
        if owner != self.uid or _uids(_read_at(fd, 'status', 65536)) != (self.uid,) * 4:
            raise PickerError('Process belongs to another user or changed credentials')
        birth = _birth(_read_at(fd, 'stat', 65536), pid)
        raw_exe = os.readlink('exe', dir_fd=fd)
        if raw_exe.endswith(' (deleted)'):
            raise PickerError('The running executable has been removed')
        executable, exe_info = _canonical(raw_exe, executable=True)
        running_exe = os.stat('exe', dir_fd=fd)
        if (exe_info.st_dev, exe_info.st_ino) != (running_exe.st_dev, running_exe.st_ino):
            raise PickerError('Executable changed on disk; refresh the process list')
        env = _environment(_read_at(fd, 'environ', MAX_ENV))
        prefix = prefix_info = None
        if env.get('WINEPREFIX'):
            prefix, prefix_info = _canonical(env['WINEPREFIX'], directory=True)
        kind = self.discovery.classify({'env': env})
        appids = {env[name] for name in ('SteamAppId', 'STEAM_COMPAT_APP_ID') if env.get(name)}
        appid = next(iter(appids)) if len(appids) == 1 else None
        if appid and (not appid.isascii() or not appid.isdigit() or
                      not 0 < int(appid) <= 2**32 - 1):
            appid = None
        if appid and prefix and prefix.name == 'pfx' and prefix.parent.name.isdigit():
            if int(prefix.parent.name) != int(appid):
                appid = None
        name = _read_at(fd, 'comm', 256).decode('utf-8', errors='replace').strip()
        name = ''.join(c if ord(c) >= 32 and ord(c) != 127 else ' ' for c in name)
        return Candidate(pid, owner, birth, name or executable.name, kind, executable,
                         prefix, (), 0, (), appid, exe_info.st_dev, exe_info.st_ino,
                         prefix_info.st_dev if prefix_info else None,
                         prefix_info.st_ino if prefix_info else None)

    def _held(self, fd, network):
        directory = os.open('fd', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
        result = set()
        try:
            with os.scandir(directory) as entries:
                for count, entry in enumerate(entries):
                    if count >= MAX_FDS:
                        raise PickerError('Process has too many file descriptors; cannot verify it completely')
                    try:
                        matched = _SOCKET.fullmatch(os.readlink(entry.name, dir_fd=directory))
                        if matched and int(matched[1]) in network:
                            result.add(int(matched[1]))
                    except FileNotFoundError:
                        continue
        finally:
            os.close(directory)
        return tuple(sorted(result))

    def _snapshot(self, pid, network):
        fd = os.open(self.proc_root / str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            before = self._identity(fd, pid)
            inodes = self._held(fd, network)
            after = self._identity(fd, pid)
            if _identity_key(before) != _identity_key(after) or not inodes:
                raise PickerError('Process changed or has no verifiable network socket')
            return replace(after, inodes=inodes, socket_count=len(inodes),
                           transports=tuple(sorted({network[inode][0] for inode in inodes})))
        finally:
            os.close(fd)

    def list_candidates(self):
        try:
            network = self._network()
            candidates = []
            with os.scandir(self.proc_root) as entries:
                count = 0
                for entry in entries:
                    if not entry.name.isdigit():
                        continue
                    count += 1
                    if count > MAX_PROCESSES:
                        raise PickerError('Process scan limit reached; refresh after closing unused applications')
                    try:
                        candidates.append(self._snapshot(int(entry.name), network))
                    except (OSError, ValueError, UnicodeError):
                        continue
            return sorted(candidates, key=lambda item: (item.name.casefold(), item.pid))
        except PickerError:
            raise
        except (OSError, ValueError, UnicodeError) as error:
            raise PickerError('Cannot inspect current-user network processes: ' + str(error)) from None

    def revalidate(self, candidate):
        try:
            if candidate.uid != self.uid:
                raise PickerError('Process belongs to another user')
            current = self._snapshot(candidate.pid, self._network())
            if (_identity_key(candidate) != _identity_key(current) or
                    not set(candidate.inodes).intersection(current.inodes)):
                raise PickerError('Process or socket changed; refresh and select it again')
        except (OSError, ValueError, UnicodeError) as error:
            if isinstance(error, PickerError):
                raise
            raise PickerError('Selected process exited or is no longer readable; refresh the list') from None

    def _mapped_paths(self, candidate):
        self.revalidate(candidate)
        fd = os.open(self.proc_root / str(candidate.pid), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            before = self._identity(fd, candidate.pid)
            if _identity_key(before) != _identity_key(candidate):
                raise PickerError('Selected process changed')
            maps = _read_at(fd, 'maps', MAX_FILE).decode('utf-8', errors='strict')
            result = {}
            for row in maps.splitlines():
                fields = row.split(None, 5)
                if len(fields) != 6:
                    continue
                path = fields[5]
                if not path.startswith('/') or path.endswith(' (deleted)') or not path.lower().endswith('.exe'):
                    continue
                try:
                    path, info = _canonical(path)
                    major, minor = fields[3].split(':')
                    mapped_device = os.makedev(int(major, 16), int(minor, 16))
                    mapped_inode = int(fields[4], 10)
                    if mapped_inode <= 0 or (mapped_device, mapped_inode) != (info.st_dev, info.st_ino):
                        continue
                except (OSError, ValueError, OverflowError):
                    continue
                if path.suffix.lower() == '.exe':
                    result[path] = (mapped_device, mapped_inode)
                if len(result) > MAX_IMAGES:
                    raise PickerError('Too many mapped Windows executables; choose the game file explicitly')
            if _identity_key(self._identity(fd, candidate.pid)) != _identity_key(candidate):
                raise PickerError('Selected process changed while reading its mapped images')
            return result
        finally:
            os.close(fd)

    @staticmethod
    def _windows_path(prefix, path):
        roots = {}
        with os.scandir(prefix / 'dosdevices') as entries:
            for count, entry in enumerate(entries):
                if count >= 64:
                    raise PickerError('Too many Wine drive mappings')
                matched = _DRIVE.fullmatch(entry.name)
                if not matched or not entry.is_symlink():
                    continue
                try:
                    target, _info = _canonical(Path(entry.path), directory=True)
                except (OSError, ValueError):
                    # An absent removable drive need not hide a verified game
                    # on another drive. Only usable roots can translate it.
                    continue
                drive = matched[1].upper()
                if drive in roots and roots[drive] != target:
                    raise PickerError('Conflicting Wine drive mappings')
                roots[drive] = target
        choices = []
        for drive, target in roots.items():
            try:
                relative = path.relative_to(target)
            except ValueError:
                continue
            if not relative.parts or any(any(c in part for c in '\\<>:"|?*') or
                                         part.endswith((' ', '.')) for part in relative.parts):
                continue
            choices.append((-len(target.parts), drive, str(PureWindowsPath(drive + ':\\', *relative.parts))))
        if not choices:
            raise PickerError('The selected file is not visible through this prefix\'s verified Wine drives')
        return min(choices)[2]

    @staticmethod
    def _pe(path):
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size < 64:
                raise PickerError('Choose an existing Windows PE executable')
            dos = os.read(fd, 64)
            if len(dos) != 64 or dos[:2] != b'MZ':
                raise PickerError('The selected file is not a Windows PE executable')
            offset = struct.unpack_from('<I', dos, 60)[0]
            if offset < 64 or offset > min(1024 * 1024, info.st_size - 26):
                raise PickerError('Malformed Windows PE header')
            os.lseek(fd, offset, os.SEEK_SET)
            header = os.read(fd, 26)
            if len(header) != 26 or header[:4] != b'PE\0\0':
                raise PickerError('Malformed Windows PE signature')
            machine, sections = struct.unpack_from('<HH', header, 4)
            optional, flags, magic = struct.unpack_from('<HHH', header, 20)
            if ((machine, magic) not in ((0x14c, 0x10b), (0x8664, 0x20b)) or not 1 <= sections <= 96 or
                    not flags & 2 or flags & 0x2000 or magic not in (0x10b, 0x20b) or
                    optional < (96 if magic == 0x10b else 112) or
                    offset + 24 + optional + sections * 40 > info.st_size):
                raise PickerError('Unsupported or malformed Windows executable image')
            current = path.stat()
            if (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns) != (
                    current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns):
                raise PickerError('Windows executable changed while it was inspected')
            return info
        finally:
            os.close(fd)

    def _image_from_file(self, candidate, path):
        if candidate.prefix is None:
            raise PickerError('A verified Wine prefix is required to translate a Windows file path')
        path, _info = _canonical(path)
        if path.suffix.lower() != '.exe':
            raise PickerError('Choose the actual game .exe file')
        info = self._pe(path)
        windows = self._windows_path(candidate.prefix, path)
        self._windows_identity(windows)
        return ImageCandidate(path, windows, info.st_dev, info.st_ino, info.st_size,
                              info.st_mtime_ns, info.st_ctime_ns)

    def image_from_file(self, candidate, path):
        try:
            self.revalidate(candidate)
            image = self._image_from_file(candidate, path)
            self.revalidate(candidate)
            return image
        except PickerError:
            raise
        except (OSError, ValueError, UnicodeError):
            raise PickerError('Windows image or Wine drive mapping is unavailable; refresh the selection') from None

    def windows_images(self, candidate):
        try:
            if candidate.prefix is None:
                self.revalidate(candidate)
                return []
            result = []
            mapped = self._mapped_paths(candidate)
            for path in sorted(mapped, key=lambda value: str(value).casefold()):
                try:
                    image = self._image_from_file(candidate, path)
                    if (image.device, image.inode) == mapped[path]:
                        result.append(replace(image, observed=True))
                except PickerError:
                    continue
            self.revalidate(candidate)
            return result
        except PickerError:
            raise
        except (OSError, ValueError, UnicodeError):
            raise PickerError('Cannot inspect the selected process\'s Windows images') from None

    @staticmethod
    def _windows_identity(identity):
        identity = _field(identity)
        parsed = PureWindowsPath(identity)
        if not parsed.is_absolute() or parsed.suffix.lower() != '.exe' or len(identity.encode('utf-8')) >= 512:
            raise PickerError('Choose a full Windows executable identity confirmed for this game')
        return identity

    def mapping(self, candidate, windows_identity=None, image=None):
        self.revalidate(candidate)
        if windows_identity is not None and image is not None:
            raise PickerError('Select one Windows identity source')
        if image is not None:
            current = self.image_from_file(candidate, image.path)
            if replace(current, observed=image.observed) != image:
                raise PickerError('Windows file or drive mapping changed; select it again')
            if image.observed and self._mapped_paths(candidate).get(image.path) != (image.device, image.inode):
                raise PickerError('The selected image is no longer mapped by the process')
            identity = current.windows_path
        else:
            identity = self._windows_identity(windows_identity)
        if candidate.kind != 'native' and candidate.prefix is None:
            raise PickerError('Wine/Proton did not expose a verifiable WINEPREFIX; choose a supported process')
        source = 'wineprefix:' + str(candidate.prefix) if candidate.prefix else str(candidate.executable)
        fields = [source, identity]
        if candidate.prefix:
            fields.append(str(candidate.executable))
        if len('\t'.join(_field(value) for value in fields).encode('utf-8')) > 4096:
            raise PickerError('Mapping exceeds the supported length')
        self.revalidate(candidate)
        return '\t'.join(fields) + '\n'
