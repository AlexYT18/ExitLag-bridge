"""Unprivileged client operations, called outside the Tk thread.
SPDX-License-Identifier: GPL-3.0-only
"""
import os
import subprocess
import stat
from bridge_setup.core import console_output


def environment(state, token=None):
    env = os.environ.copy()
    for name in list(env):
        if name.startswith('EXITLAG_') or name in ('WINEDLLPATH', 'WINELOADER', 'QT_QUICK_BACKEND', 'QT_OPENGL'):
            env.pop(name, None)
    env.update(WINEPREFIX=str(state / 'prefix'), WINEDEBUG='-all')
    if token is not None:
        env.update(QSG_RHI_BACKEND='opengl', EXITLAG_NETD='127.0.0.1:51900', EXITLAG_NETD_TOKEN='Z:' + str(token))
    return env


def client_present(state):
    result = subprocess.run([str(state / 'runtime/bin/wine'), 'tasklist.exe', '/FI', 'IMAGENAME eq ExitLag.exe', '/NH'],
                            env=environment(state), capture_output=True, timeout=10)
    if result.returncode:
        return None
    return b'exitlag.exe' in console_output(result.stdout).lower()


def stop_client(state):
    result = subprocess.run([str(state / 'runtime/bin/wine'), 'taskkill.exe', '/IM', 'ExitLag.exe', '/F'],
                            env=environment(state), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode and client_present(state) is not False:
        return 'Не удалось подтвердить закрытие ExitLag. Проверьте окно клиента.'
    return ''


def open_client_log(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or info.st_mode & 0o077):
            raise ValueError('Client log must be a private owned regular file')
        return fd
    except BaseException:
        os.close(fd)
        raise
