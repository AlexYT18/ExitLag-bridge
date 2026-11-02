"""Standard-library helpers for isolated, synthetic netfilter integration tests."""

import os
import shutil
import socket
import struct
import subprocess
import sys
import time


MAGIC = 0x314C5845
VERSION = 3
MAX_PAYLOAD = 131072
HEADER = struct.Struct('<IHHI')
HELLO = 0x0001
HELLO_ACK = 0x0002
PING = 0x0003
PONG = 0x0004


class PrerequisiteUnavailable(Exception):
    """The host cannot safely execute this integration scenario."""


def require_isolation():
    """Refuse mutation outside the wrapper's separate network/PID namespaces."""
    if os.geteuid() != 0:
        raise PrerequisiteUnavailable('needs namespace root via tests/run-isolated.sh')
    if os.environ.get('EXITLAG_TEST_ISOLATED') != '1':
        raise PrerequisiteUnavailable('use tests/run-isolated.sh; isolation marker is absent')
    for kind, variable in (('net', 'EXITLAG_TEST_HOST_NETNS'),
                           ('pid', 'EXITLAG_TEST_HOST_PIDNS')):
        original = os.environ.get(variable)
        current = os.readlink(f'/proc/self/ns/{kind}')
        if not original or current == original:
            raise PrerequisiteUnavailable(f'{kind} namespace differs from host: not established')


def required_tool(name):
    executable = shutil.which(name)
    if executable is None:
        raise PrerequisiteUnavailable(f'missing integration dependency: {name}')
    return executable


def checked(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def table_exists(nft):
    return subprocess.run([nft, 'list', 'table', 'inet', 'exitlag'],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def available_port():
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        return reservation.getsockname()[1]


def receive_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise RuntimeError('unexpected IPC EOF')
        data.extend(part)
    return bytes(data)


def receive_frame(sock):
    magic, kind, flags, length = HEADER.unpack(receive_exact(sock, HEADER.size))
    if magic != MAGIC or flags != 0 or length > MAX_PAYLOAD:
        raise RuntimeError(f'invalid IPC frame: magic={magic:#x}, flags={flags}, length={length}')
    return kind, receive_exact(sock, length)


def send_frame(sock, kind, body=b''):
    if len(body) > MAX_PAYLOAD:
        raise RuntimeError('test attempted oversized frame')
    sock.sendall(HEADER.pack(MAGIC, kind, 0, len(body)) + body)


def respond_to_heartbeat(sock, kind, body):
    if kind != PING:
        return False
    if body:
        raise RuntimeError('PING unexpectedly contains a payload')
    send_frame(sock, PONG)
    return True


def wait_for_log(path, text, process, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if path.exists() and text in path.read_text(errors='replace'):
            return
        if process.poll() is not None:
            detail = path.read_text(errors='replace') if path.exists() else '(no helper log)'
            raise RuntimeError(f'helper exited during startup ({process.returncode}): {detail}')
        time.sleep(.02)
    raise RuntimeError(f'timed out waiting for helper log {text!r}')


def authenticate(port, token_path, process):
    deadline = time.monotonic() + 5
    while not token_path.exists() and time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('helper exited before publishing its token')
        time.sleep(.02)
    token = bytes.fromhex(token_path.read_text().strip())
    if len(token) != 32:
        raise RuntimeError('invalid test session token length')
    peer = socket.create_connection(('127.0.0.1', port), timeout=5)
    try:
        send_frame(peer, HELLO, struct.pack('<IIQ32s', VERSION, 4242, 0, token))
        kind, acknowledgement = receive_frame(peer)
        if kind != HELLO_ACK or len(acknowledgement) != 16:
            raise RuntimeError('invalid helper HELLO_ACK framing')
        version, helper_pid, _capabilities = struct.unpack('<IIQ', acknowledgement)
        if version != VERSION or helper_pid != process.pid:
            raise RuntimeError('helper HELLO_ACK does not match this v3 session')
        return peer
    except BaseException:
        peer.close()
        raise


def stop_process(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    else:
        process.wait()


def close_socket(sock):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    sock.close()


def run_main(function):
    try:
        return function()
    except PrerequisiteUnavailable as error:
        print(f'SKIP: {error}', file=sys.stderr)
        return 77
