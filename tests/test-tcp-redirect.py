#!/usr/bin/env python3
"""Synthetic v3 IPC -> real IPv4 NFQUEUE/DNAT -> local proxy integration.

Run only through tests/run-isolated.sh. The routing peer is a mock, not ExitLag;
this demonstrates one TCP mechanism and reverse path, not game compatibility.
"""

import os
import queue
import socket
import struct
import subprocess
import tempfile
import threading
from pathlib import Path

from integration_support import (
    authenticate, available_port, checked, close_socket, receive_exact,
    receive_frame, require_isolation, required_tool, respond_to_heartbeat,
    run_main, send_frame, stop_process, table_exists, wait_for_log,
)


ROOT = Path(__file__).resolve().parent.parent
REQUEST = struct.Struct('<QQIIB3sH28s28s')
REPLY = struct.Struct('<QII28sBB2s')


def main():
    require_isolation()  # Before sockets, helper startup or firewall mutation.
    nft = required_tool('nft')
    required_tool('ip')
    helper_binary = ROOT / 'backend/exitlag-netd'
    if not helper_binary.is_file():
        raise RuntimeError('build backend/exitlag-netd before the integration test')
    if table_exists(nft):
        raise RuntimeError('refusing to touch pre-existing table inet exitlag')
    original_ip = os.environ.get('PROBE_DEST', '192.0.2.2')
    original_port = int(os.environ.get('PROBE_PORT', '3724'))
    ipc_port = available_port()
    observed, errors = {}, queue.Queue()
    stopping = threading.Event()
    heartbeat = threading.Event()
    table_installed = False
    helper = shim = None
    shim_thread = proxy_thread = None
    proxy = socket.socket()
    proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy.bind(('127.0.0.1', 0))
    proxy.listen(1)
    proxy.settimeout(5)
    proxy_port = proxy.getsockname()[1]

    def proxy_worker():
        try:
            connection, peer = proxy.accept()
            with connection:
                connection.settimeout(5)
                observed['proxy_peer'] = peer
                observed['payload'] = receive_exact(connection, 4)
                connection.sendall(b'pong')
        except Exception as error:
            if not stopping.is_set():
                errors.put(error)

    def shim_worker():
        try:
            while not stopping.is_set():
                kind, body = receive_frame(shim)
                if respond_to_heartbeat(shim, kind, body):
                    heartbeat.set()
                    continue
                if kind != 0x0010 or len(body) != REQUEST.size:
                    raise RuntimeError(f'unexpected callback {kind:#x}/{len(body)}')
                tag, endpoint, pid, flag, direction, _reserved, family, local, remote = REQUEST.unpack(body)
                if family != 2 or direction != 2:
                    raise RuntimeError(f'unexpected TCP family/direction {family}/{direction}')
                observed['request'] = {
                    'tag': tag, 'endpoint': endpoint, 'pid': pid, 'flag': flag,
                    'local': (socket.inet_ntoa(local[4:8]), struct.unpack('!H', local[2:4])[0]),
                    'remote': (socket.inet_ntoa(remote[4:8]), struct.unpack('!H', remote[2:4])[0]),
                }
                target = struct.pack('<H', 2) + struct.pack('!H', proxy_port) + socket.inet_aton('127.0.0.1') + bytes(20)
                send_frame(shim, 0x0011, REPLY.pack(tag, 1, 0x210, target, 1, 1, bytes(2)))
        except Exception as error:
            if not stopping.is_set():
                errors.put(error)

    with tempfile.TemporaryDirectory(prefix='exitlag-tcp-test-') as work:
        log = Path(work) / 'netd.log'
        token = Path(work) / 'token'
        try:
            helper_env = os.environ.copy()
            helper_env.pop('EXITLAG_IDENTITY_MAP', None)
            helper = subprocess.Popen([
                str(helper_binary), '--queue', '0', '--port', str(ipc_port),
                '--timeout-ms', '1000', '--apply-tcp', '--peer-uid', str(os.geteuid()),
                '--token-file', str(token), '--log', str(log),
            ], env=helper_env)
            wait_for_log(log, 'bound NFQUEUE 0', helper)
            shim = authenticate(ipc_port, token, helper)
            shim.settimeout(5)
            shim_thread = threading.Thread(target=shim_worker, daemon=True)
            proxy_thread = threading.Thread(target=proxy_worker, daemon=True)
            shim_thread.start()
            if not heartbeat.wait(5):
                if not errors.empty():
                    raise errors.get_nowait()
                raise RuntimeError('no helper heartbeat observed by synthetic peer')
            proxy_thread.start()

            env = os.environ.copy()
            env.update(QUEUE_NUM='0', TEST_DEST=original_ip, ENABLE_UDP_OBSERVE='0', ENABLE_UDP_STEER='0')
            env.pop('EXL_USER_UID', None)
            checked(str(ROOT / 'backend/nft-setup.sh'), env=env, stdout=subprocess.DEVNULL)
            table_installed = True
            with socket.socket() as client:
                client.settimeout(5)
                client.connect((original_ip, original_port))
                observed['client_local'] = client.getsockname()
                observed['client_peer'] = client.getpeername()
                client.sendall(b'ping')
                observed['reply'] = receive_exact(client, 4)
            proxy_thread.join(3)
            if proxy_thread.is_alive():
                raise RuntimeError('proxy worker did not finish')
            if not errors.empty():
                raise errors.get_nowait()
            rules = checked(nft, 'list', 'table', 'inet', 'exitlag', text=True, capture_output=True).stdout
            assert observed['request']['remote'] == (original_ip, original_port), observed
            assert observed['request']['pid'] == os.getpid(), observed['request']
            assert observed['client_peer'] == (original_ip, original_port), observed
            assert observed['payload'] == b'ping' and observed['reply'] == b'pong', observed
            assert f'127.0.0.1 . {proxy_port}' in rules, rules
            assert 'DNAT armed; ACCEPT (active)' in log.read_text(errors='replace')
            print(f'synthetic callback: {observed["request"]["remote"]} -> 127.0.0.1:{proxy_port}')
            print('heartbeat, TCP payload in both directions and original application peer: PASS')
        except Exception:
            if not errors.empty():
                raise errors.get_nowait()
            raise
        finally:
            stopping.set()
            close_socket(shim)
            close_socket(proxy)
            cleanup_errors = []
            for worker in (shim_thread, proxy_thread):
                if worker is not None and worker.ident is not None:
                    worker.join(6)
                    if worker.is_alive():
                        cleanup_errors.append('integration worker failed to stop')
            try:
                if table_installed:
                    checked(str(ROOT / 'backend/nft-teardown.sh'), stdout=subprocess.DEVNULL)
            except Exception as error:
                cleanup_errors.append(str(error))
            try:
                stop_process(helper)
            except Exception as error:
                cleanup_errors.append(str(error))
            if token.exists():
                cleanup_errors.append('helper session token remains')
            if table_installed and table_exists(nft):
                cleanup_errors.append('table inet exitlag remains')
            if cleanup_errors:
                raise RuntimeError('integration cleanup failed: ' + '; '.join(cleanup_errors))
    print('synthetic IPv4 TCP integration: PASS; owned table/helper/token cleaned up')
    return 0


if __name__ == '__main__':
    raise SystemExit(run_main(main))
