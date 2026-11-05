"""Unprivileged desktop presentation and bounded, redacted diagnostics.
SPDX-License-Identifier: GPL-3.0-only
"""
from dataclasses import dataclass
import os
from pathlib import Path, PureWindowsPath
import platform
import re
import stat
import unicodedata


@dataclass(frozen=True)
class SessionView:
    state: str
    backend: str
    client: str
    route: str
    can_confirm_route: bool = False


def session_view(*, helper_running=False, client_running=False, starting=False,
                 stopping=False, backend_ready=False, error=''):
    """Process/readiness observations never establish actual relay traffic."""
    if error:
        state = 'Ошибка'
    elif stopping:
        state = 'Остановка'
    elif client_running:
        state = 'Клиент запущен'
    elif starting or helper_running:
        state = 'Запуск'
    else:
        state = 'Остановлено'
    backend = ('Готовность получена' if backend_ready and helper_running else
               'Supervisor запущен; готовность не проверена' if helper_running else 'Не запущен')
    return SessionView(state, backend,
                       'Запущен' if client_running else 'Не запущен',
                       'Маршрут не подтверждён')


def display_path(path):
    """Display a basename only; full paths remain internal to identity checks."""
    if path is None or not str(path):
        return 'Недоступно'
    value = str(path).rstrip('/\\')
    name = PureWindowsPath(value).name if '\\' in value else Path(value).name
    name = ''.join(c for c in name if not unicodedata.category(c).startswith('C'))
    return '…/' + name if name else 'Скрытый путь'


_SECRET = re.compile(r'(?i)(token|passw(?:or)?d|passwd|secret|authorization|'
                     r'authentication|bearer|cookie|credential|subscription|'
                     r'auth[_ -]?(?:key|token)|api[_ -]?key|access[_ -]?key|private[_ -]?key|session[_ -]?(?:id|key))')
_WINDOWS_PATH = re.compile(r'(?<![\w])(?:[A-Za-z]:[\\/]|\\\\)[^\r\n]*')
_POSIX_PATH = re.compile(r'(?<![\w:])/(?!/)[^\r\n]*')
_HEX = re.compile(r'(?i)\b[0-9a-f]{24,}\b')
_JWT = re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b')
_EMAIL = re.compile(r'\b[^\s@]+@[^\s@]+\.[^\s@]+\b')
_IPV4 = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
_IPV6 = re.compile(r'(?i)(?<![\w])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]*')


def redact(text):
    """Conservative display/export filter; callers must never read token files.

    Paths consume the remainder of their line intentionally: spaces and quotes
    are valid private path characters, so guessing their boundary can leak data.
    """
    safe = ''.join(c for c in str(text) if c in '\n\t' or not unicodedata.category(c).startswith('C'))
    result = []
    secret_block = False
    for line in safe.splitlines():
        if secret_block:
            if line.strip():
                result.append('[чувствительная запись скрыта]')
                continue
            secret_block = False
        if _SECRET.search(line):
            # A key without an inline value may introduce a multiline secret.
            # Hide its continuation until a blank line rather than guess it.
            secret_block = bool(re.search(r'[:=]\s*$', line))
            result.append('[чувствительная запись скрыта]')
            continue
        for pattern, replacement in ((_JWT, '[секрет скрыт]'), (_HEX, '[идентификатор скрыт]'),
                                     (_EMAIL, '[адрес скрыт]'), (_WINDOWS_PATH, '[путь скрыт]'),
                                     (_POSIX_PATH, '[путь скрыт]'), (_IPV4, '[IP скрыт]'),
                                     (_IPV6, '[IP скрыт]')):
            line = pattern.sub(replacement, line)
        result.append(line)
    return '\n'.join(result)


def read_log_tail(path, *, expected_uid, max_bytes=32768):
    """Read a capped tail of an owned private log, without following links."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= 65536:
        raise ValueError('Diagnostic read limit is outside safe bounds')
    path = Path(path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        parent = os.fstat(directory)
        if parent.st_uid != expected_uid or parent.st_mode & 0o022:
            raise ValueError('Diagnostic directory ownership or permissions are unsafe')
        fd = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=directory)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or
                    info.st_nlink != 1 or info.st_mode & 0o077):
                raise ValueError('Diagnostic log must be a private owned regular file')
            sample = os.pread(fd, min(512, max_bytes), 0)
            encoding = 'utf-8'
            if sample.startswith(b'\xff\xfe'):
                encoding = 'utf-16le'
            elif sample.startswith(b'\xfe\xff'):
                encoding = 'utf-16be'
            elif sample and sample.count(0) > len(sample) // 4:
                encoding = ('utf-16le' if sample[1::2].count(0) >= sample[::2].count(0)
                            else 'utf-16be')
            offset = max(0, info.st_size - max_bytes)
            if encoding != 'utf-8' and offset % 2:
                offset += 1
            os.lseek(fd, offset, os.SEEK_SET)
            data = os.read(fd, max_bytes)
            text = data.decode(encoding, errors='replace')
            # Never begin a redacted tail in the middle of a secret-bearing line.
            if offset:
                # A multiline secret's key can precede the bounded window.
                # Resume only after a complete blank-line record boundary.
                text = text.replace('\r\n', '\n').replace('\r', '\n')
                boundary = re.search(r'\n[ \t]*\n', text)
                text = text[boundary.end():] if boundary else ''
            return redact(text)
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def diagnostics_snapshot(state):
    """Collect only two known logs; never request elevation or read IPC tokens."""
    uid = os.getuid()
    sections = [f'ExitLag Bridge · Linux\nОС: {platform.system()}\n'
                f'Kernel: {platform.release()}\nАрхитектура: {platform.machine()}\n'
                'Ping, потери, jitter: не измеряются\n'
                'Маршрут: нет доступного GUI подтверждения от backend']
    for label, path, owner in (
            ('Клиент Wine', Path(state) / 'client.log', uid),
            ('Backend', Path('/run') / f'exitlag-bridge-{uid}' / 'backend.log', 0)):
        try:
            value = read_log_tail(path, expected_uid=owner)
            sections.append(label + '\n' + (value or 'Нет доступных строк'))
        except FileNotFoundError:
            sections.append(label + '\nЛог пока не создан')
        except PermissionError:
            sections.append(label + '\nЛог недоступен обычному пользователю; повышение прав не запрашивается')
        except (OSError, ValueError):
            sections.append(label + '\nЧтение отклонено: небезопасный или недоступный файл')
    return redact('\n\n'.join(sections))
