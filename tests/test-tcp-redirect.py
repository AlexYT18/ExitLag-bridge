#!/usr/bin/env python3
"""Synthetic v3 IPC -> real IPv4 NFQUEUE/DNAT -> local proxy integration.

Run only through tests/run-isolated.sh. The routing peer is a mock, not ExitLag;
this demonstrates one TCP mechanism and reverse path, not game compatibility.
"""

import json
import os
import queue
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from integration_support import (
    authenticate, available_port, checked, close_socket, receive_exact,
    receive_frame, require_isolation, required_tool, respond_to_heartbeat,
    run_main, send_frame, stop_process, table_exists, wait_for_log,
)


ROOT = Path(__file__).resolve().parent.parent
REQUEST = struct.Struct('<QQIIB3sH28s28s')
REPLY = struct.Struct('<QII28sBB2s')


def proc_endpoint(value):
    address, port = value.split(':')
    return socket.inet_ntoa(bytes.fromhex(address)[::-1]), int(port, 16)


def queued_socket_inodes(local, remotes):
    """Read actual SYN_SENT rows, independently of the helper's attribution."""
    found = {}
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10 or fields[3] != '02':
            continue
        remote = proc_endpoint(fields[2])
        if proc_endpoint(fields[1]) == local and remote in remotes:
            inode = int(fields[9])
            if not inode or remote in found:
                raise RuntimeError(f'ambiguous queued socket fixture: {line}')
            found[remote] = inode
    return found


def process_holds_inode(process, inode):
    for descriptor in Path(f'/proc/{process.pid}/fd').iterdir():
        try:
            if os.readlink(descriptor) == f'socket:[{inode}]':
                return True
        except FileNotFoundError:
            continue
    return False


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
    observed, errors = {'requests': [], 'proxies': {}}, queue.Queue()
    stopping = threading.Event()
    heartbeat = threading.Event()
    release_proxies = threading.Event()
    table_installed = helper_paused = False
    helper = shim = None
    shim_thread = None
    proxy_threads, proxies, clients = [], [], []
    control = None
    destinations = [(original_ip, original_port)]
    second_port = available_port()
    while second_port == original_port:
        second_port = available_port()
    destinations.append((original_ip, second_port))
    proxy_ports = {}
    payloads = {original_port: (b'ping', b'pong'), second_port: (b'two!', b'back')}

    def proxy_worker(proxy, destination_port):
        try:
            deadline = time.monotonic() + 10
            while not stopping.is_set():
                try:
                    connection, peer = proxy.accept()
                    break
                except socket.timeout:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('local proxy did not receive its connection')
            else:
                return
            with connection:
                connection.settimeout(5)
                observed['proxies'][destination_port] = {
                    'peer': peer, 'payload': receive_exact(connection, 4),
                }
                connection.sendall(payloads[destination_port][1])
                # Preserve the first socket in ESTABLISHED while the helper
                # attributes the second; local-only matching must stay wrong
                # regardless of which row appears first in /proc.
                if not release_proxies.wait(12):
                    raise RuntimeError('proxy socket retention timed out')
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
                request = {
                    'tag': tag, 'endpoint': endpoint, 'pid': pid, 'flag': flag,
                    'local': (socket.inet_ntoa(local[4:8]), struct.unpack('!H', local[2:4])[0]),
                    'remote': (socket.inet_ntoa(remote[4:8]), struct.unpack('!H', remote[2:4])[0]),
                }
                observed['requests'].append(request)
                if request['remote'] not in destinations:
                    raise RuntimeError(f'unrelated connection was intercepted: {request}')
                proxy_port = proxy_ports[request['remote'][1]]
                target = struct.pack('<H', 2) + struct.pack('!H', proxy_port) + socket.inet_aton('127.0.0.1') + bytes(20)
                send_frame(shim, 0x0011, REPLY.pack(tag, 1, 0x210, target, 1, 1, bytes(2)))
        except Exception as error:
            if not stopping.is_set():
                errors.put(error)

    with tempfile.TemporaryDirectory(prefix='exitlag-tcp-test-') as work:
        log = Path(work) / 'netd.log'
        token = Path(work) / 'token'
        try:
            # Separate proxy ports keep the two translated 4-tuples distinct
            # even though both original sockets deliberately share a local port.
            for _address, destination_port in destinations:
                proxy = socket.socket()
                proxies.append(proxy)
                proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                proxy.bind(('127.0.0.1', 0))
                proxy.listen(1)
                proxy.settimeout(.2)
                proxy_ports[destination_port] = proxy.getsockname()[1]
                proxy_threads.append(threading.Thread(
                    target=proxy_worker, args=(proxy, destination_port), daemon=True))
            control = socket.socket()
            control.bind(('127.0.0.1', 0))
            control.listen(1)
            control.settimeout(1)
            helper_env = os.environ.copy()
            helper_env.pop('EXITLAG_IDENTITY_MAP', None)
            helper = subprocess.Popen([
                str(helper_binary), '--queue', '0', '--port', str(ipc_port),
                '--timeout-ms', '1000', '--apply-tcp', '--peer-uid', str(os.geteuid()),
                '--token-file', str(token), '--log', str(log),
            ], env=helper_env)
            wait_for_log(log, 'bound NFQUEUE 0', helper)
            shim = authenticate(ipc_port, token, helper)
            shim.settimeout(10)
            shim_thread = threading.Thread(target=shim_worker, daemon=True)
            shim_thread.start()
            if not heartbeat.wait(5):
                if not errors.empty():
                    raise errors.get_nowait()
                raise RuntimeError('no helper heartbeat observed by synthetic peer')
            for worker in proxy_threads:
                worker.start()

            env = os.environ.copy()
            env.update(QUEUE_NUM='0', TEST_DEST=original_ip, ENABLE_UDP_OBSERVE='0', ENABLE_UDP_STEER='0')
            env.pop('EXL_USER_UID', None)
            checked(str(ROOT / 'backend/nft-setup.sh'), env=env, stdout=subprocess.DEVNULL)
            table_installed = True

            # Stop the helper before either connect: both real kernel rows must
            # exist before its first lookup, so a local-only first match cannot
            # accidentally pass by observing one socket at a time.
            helper.send_signal(signal.SIGSTOP)
            helper_paused = True
            deadline = time.monotonic() + 3
            while '\nState:\tT' not in Path(f'/proc/{helper.pid}/status').read_text():
                if helper.poll() is not None or time.monotonic() >= deadline:
                    raise RuntimeError('helper did not stop before concurrent socket setup')
                time.sleep(.01)

            # This unrelated loopback TCP flow must work while the queue helper
            # is stopped and must never reach the synthetic routing callback.
            with socket.create_connection(control.getsockname(), timeout=1) as control_client:
                control_connection, _peer = control.accept()
                with control_connection:
                    control_connection.settimeout(1)
                    control_client.sendall(b'ctrl')
                    assert receive_exact(control_connection, 4) == b'ctrl'
                    control_connection.sendall(b'safe')
                    assert receive_exact(control_client, 4) == b'safe'

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route_probe:
                route_probe.connect(destinations[0])  # Route lookup; no datagram is sent.
                local_ip = route_probe.getsockname()[0]
            with socket.socket() as reservation:
                reservation.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                reservation.bind((local_ip, 0))
                local = reservation.getsockname()
                for index, remote in enumerate(destinations):
                    result = Path(work) / f'client-{index}.json'
                    child = subprocess.Popen([
                        sys.executable, str(ROOT / 'tests/tcp-attribution-client.py'),
                        local[0], str(local[1]), remote[0], str(remote[1]),
                        payloads[remote[1]][0].decode('ascii'), str(result),
                    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT, text=True)
                    clients.append((child, remote, result))

            def check_clients():
                for child, remote, _result in clients:
                    if child.poll() is not None:
                        raise RuntimeError(f'client {remote} exited ({child.returncode}): {child.stdout.read()}')
                if not errors.empty():
                    raise errors.get_nowait()

            deadline = time.monotonic() + 5
            while True:
                check_clients()
                inodes = queued_socket_inodes(local, destinations)
                if len(inodes) == 2 and all(
                        process_holds_inode(child, inodes[remote])
                        for child, remote, _result in clients):
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(f'two distinct SYN_SENT socket owners were not established: {inodes}')
                time.sleep(.01)
            assert len(set(inodes.values())) == 2, inodes
            helper.send_signal(signal.SIGCONT)
            helper_paused = False

            deadline = time.monotonic() + 10
            while not all(result.exists() for _child, _remote, result in clients):
                check_clients()
                if time.monotonic() >= deadline:
                    raise RuntimeError('concurrent clients did not finish both proxy echoes')
                time.sleep(.01)
            release_proxies.set()
            for worker in proxy_threads:
                worker.join(3)
                if worker.is_alive():
                    raise RuntimeError('proxy worker did not finish')
            if not errors.empty():
                raise errors.get_nowait()
            rules = checked(nft, 'list', 'table', 'inet', 'exitlag', text=True, capture_output=True).stdout
            # A slow CI host may queue retransmitted SYNs while the helper is
            # stopped. Every resulting callback must still name the same exact
            # owner; two unique destination flows and two echoes are required.
            requests = observed['requests']
            assert len(requests) >= 2, observed
            assert len({request['tag'] for request in requests}) == len(requests), observed
            assert len({request['endpoint'] for request in requests}) == len(requests), observed
            assert {request['remote'] for request in requests} == set(destinations), observed
            assert len({child.pid for child, _remote, _result in clients}) == 2
            for child, remote, result in clients:
                report = json.loads(result.read_text())
                matching = [request for request in requests if request['remote'] == remote]
                assert child.pid == report['pid'], report
                assert tuple(report['local']) == local, report
                assert all(request['pid'] == child.pid for request in matching), (matching, report)
                assert all(request['local'] == local for request in matching), (matching, report)
                assert tuple(report['peer']) == remote, report
                assert report['reply'].encode('ascii') == payloads[remote[1]][1], report
                assert observed['proxies'][remote[1]]['payload'] == payloads[remote[1]][0], observed
                assert f'127.0.0.1 . {proxy_ports[remote[1]]}' in rules, rules
                print(f'synthetic callback: pid={child.pid} {local} -> {remote} -> 127.0.0.1:{proxy_ports[remote[1]]}')
            assert log.read_text(errors='replace').count('DNAT armed; ACCEPT (active)') == len(requests)
            for child, remote, _result in clients:
                output, _unused = child.communicate(input='done\n', timeout=3)
                if child.returncode:
                    raise RuntimeError(f'client {remote} failed ({child.returncode}): {output}')
            print('same local tuple, distinct process owners and original peers, two-way payloads: PASS')
            print('heartbeat and unrelated loopback control flow without interception: PASS')
        except Exception:
            if not errors.empty():
                raise errors.get_nowait()
            raise
        finally:
            # A stopped helper cannot process SIGTERM or remove its token.
            # Always resume it before closing IPC, tearing down rules or stop().
            if helper_paused and helper is not None and helper.poll() is None:
                try:
                    helper.send_signal(signal.SIGCONT)
                except ProcessLookupError:
                    pass
                helper_paused = False
            stopping.set()
            release_proxies.set()
            close_socket(shim)
            for proxy in proxies:
                close_socket(proxy)
            close_socket(control)
            cleanup_errors = []
            for child, _remote, _result in clients:
                try:
                    stop_process(child)
                    for pipe in (child.stdin, child.stdout):
                        if pipe is not None:
                            pipe.close()
                except Exception as error:
                    cleanup_errors.append(str(error))
            for worker in [shim_thread, *proxy_threads]:
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
