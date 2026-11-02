#!/usr/bin/env python3
"""Real isolated regression for stale TCP maps and per-packet authorization.

The callback peer is synthetic. Each probe uses a fresh TCP tuple; cached
conntrack translations and live ExitLag/game compatibility are separate tests.
Run through tests/run-isolated.sh, never against the host firewall.
"""

import json
import os
import queue
import secrets
import selectors
import socket
import struct
import subprocess
import sys
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
AUTH_PRIORITY, OTHER_PRIORITY, OTHER_MARK = 0x80000000, 4, 0x00010000
HOST_V4, PEER_V4 = '198.18.77.1', '198.18.77.2'
HOST_V6, PEER_V6 = '2001:db8:77::1', '2001:db8:77::2'


def echo_server(arguments):
    """Private peer process: bind both families before publishing readiness."""
    v4, v6, ready_path = arguments
    servers = []
    try:
        with selectors.DefaultSelector() as poller:
            ports = {}
            for family, address in ((socket.AF_INET, v4), (socket.AF_INET6, v6)):
                server = socket.socket(family)
                servers.append(server)
                server.bind((address, 0))
                server.listen(16)
                poller.register(server, selectors.EVENT_READ)
                ports[str(family)] = server.getsockname()[1]
            Path(ready_path).write_text(json.dumps(ports) + '\n')
            while True:
                for key, _events in poller.select(20):
                    connection, _peer = key.fileobj.accept()
                    with connection:
                        connection.settimeout(3)
                        connection.sendall(b'ORIGINAL:' + receive_exact(connection, 4))
    finally:
        for server in servers:
            server.close()


def main():
    require_isolation()  # Before every socket, subprocess or firewall mutation.
    if sys.argv[1:2] == ['--echo-server']:
        if len(sys.argv) != 5:
            raise RuntimeError('invalid private echo-server arguments')
        return echo_server(sys.argv[2:])
    if sys.argv[1:]:
        raise RuntimeError('use test-tcp-authorization.py via tests/run-isolated.sh')
    nft, ip = required_tool('nft'), required_tool('ip')
    helper_binary = ROOT / 'backend/exitlag-netd'
    if not helper_binary.is_file():
        raise RuntimeError('build backend/exitlag-netd before the integration test')
    if table_exists(nft):
        raise RuntimeError('refusing to touch pre-existing table inet exitlag')

    suffix = secrets.token_hex(3)
    namespace, host_if, peer_if = 'exlauth-' + suffix, 'exlah' + suffix, 'exlap' + suffix
    queue_number = 6000 + os.getpid() % 1000
    namespace_created = link_created = table_installed = False
    helper = server = shim = shim_thread = None
    listeners, workers = [], []
    stopping, shim_stopping, heartbeat = threading.Event(), threading.Event(), threading.Event()
    errors, callbacks, proxy_accepts = queue.Queue(), [], []
    mode = {'value': 'unchanged'}
    proxies = {}

    def proxy_worker(listener, family):
        try:
            while not stopping.is_set():
                try:
                    connection, _peer = listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(3)
                    proxy_accepts.append(family)
                    connection.sendall(b'PROXY:' + receive_exact(connection, 4))
        except Exception as error:
            if not stopping.is_set():
                errors.put(error)

    def mock_shim():
        try:
            while not stopping.is_set():
                kind, body = receive_frame(shim)
                if respond_to_heartbeat(shim, kind, body):
                    heartbeat.set()
                    continue
                if kind != 0x0010 or len(body) != REQUEST.size:
                    raise RuntimeError(f'unexpected TCP callback {kind:#x}/{len(body)}')
                tag, _endpoint, pid, flag, direction, _reserved, family, _local, remote = REQUEST.unpack(body)
                native_family = socket.AF_INET if family == 2 else socket.AF_INET6 if family == 23 else None
                if native_family is None or direction != 2 or pid != os.getpid():
                    raise RuntimeError(f'wrong synthetic callback identity {family}/{direction}/{pid}')
                selected = mode['value']
                callbacks.append((selected, native_family, pid))
                if selected in ('valid', 'invalid'):
                    address, port = proxies[native_family]
                    if selected == 'invalid':
                        port = 0
                    target = bytearray(28)
                    struct.pack_into('<H', target, 0, family)
                    struct.pack_into('!H', target, 2, port)
                    packed = socket.inet_pton(native_family, address)
                    offset = 4 if native_family == socket.AF_INET else 8
                    target[offset:offset + len(packed)] = packed
                    reply = REPLY.pack(tag, 1, flag | 0x200, target, 1, 1, bytes(2))
                else:
                    verdict = 2 if selected == 'no-handler' else 0
                    reply = REPLY.pack(tag, verdict, flag, remote, 0, 0, bytes(2))
                send_frame(shim, 0x0011, reply)
        except Exception as error:
            if not stopping.is_set() and not shim_stopping.is_set():
                errors.put(error)

    def counters():
        rules = json.loads(checked(nft, '-j', 'list', 'chain', 'inet', 'exitlag',
                                   'test_authorization_marks', text=True, capture_output=True).stdout)
        result = {}
        for item in rules['nftables']:
            rule = item.get('rule', {})
            if 'comment' in rule:
                result[rule['comment']] = sum(expression['counter']['packets']
                                               for expression in rule['expr'] if 'counter' in expression)
        return result

    def install_table(scope):
        nonlocal table_installed
        env = os.environ.copy()
        env.update(QUEUE_NUM=str(queue_number), TEST_DEST=scope,
                   ENABLE_UDP_OBSERVE='0', ENABLE_UDP_STEER='0')
        env.pop('EXL_USER_UID', None)
        checked(str(ROOT / 'backend/nft-setup.sh'), env=env, stdout=subprocess.DEVNULL)
        table_installed = True
        checked(nft, '-f', '-', text=True, input='''
add chain inet exitlag test_authorization_marks { type filter hook output priority -90; policy accept; }
add rule inet exitlag test_authorization_marks meta l4proto tcp tcp flags & (syn|ack) == syn meta priority & 0x80000000 != 0 counter comment "auth-bit-leaked"
add rule inet exitlag test_authorization_marks meta l4proto tcp tcp flags & (syn|ack) == syn meta priority & 0x00000004 != 0 counter comment "other-priority-preserved"
add rule inet exitlag test_authorization_marks meta l4proto tcp tcp flags & (syn|ack) == syn meta mark & 0x00010000 != 0 counter comment "other-mark-preserved"
''')

    def probe(family, remote, label, forged=False, expect_proxy=False, expect_callback=False,
              preserve_reserved=False):
        address = '127.0.0.1' if family == socket.AF_INET else '::1'
        source = address if remote[0] == address else HOST_V4 if family == socket.AF_INET else HOST_V6
        map_name = 'tcp_redirect_v4' if family == socket.AF_INET else 'tcp_redirect_v6'
        callback_count, accepts_before = len(callbacks), len(proxy_accepts)
        before = counters()
        with socket.socket(family) as client:
            client.settimeout(5)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, OTHER_MARK)
            client.setsockopt(socket.SOL_SOCKET, socket.SO_PRIORITY,
                              struct.pack('=I', OTHER_PRIORITY | (AUTH_PRIORITY if forged else 0)))
            client.bind((source, 0))
            source_port = client.getsockname()[1]
            target_address, target_port = proxies[family]
            statement = (f'add element inet exitlag {map_name} {{ {source} . {source_port} . '
                         f'{remote[0]} . {remote[1]} timeout 120s : {target_address} . {target_port} }}\n')
            checked(nft, '-f', '-', input=statement, text=True)
            client.connect(remote)
            assert client.getpeername()[:2] == remote, (label, client.getpeername(), remote)
            client.sendall(b'ping')
            expected = b'PROXY:ping' if expect_proxy else b'ORIGINAL:ping'
            reply = bytearray()
            while True:
                part = client.recv(64)
                if not part:
                    break
                reply.extend(part)
            if reply != expected:
                raise AssertionError(f'{label}: stale map redirected an unauthorized fresh connection: {reply!r}')
        if not errors.empty():
            raise errors.get_nowait()
        if expect_callback:
            assert len(callbacks) > callback_count, (label, callbacks)
            assert all(item == (mode['value'], family, os.getpid()) for item in callbacks[callback_count:]), callbacks
        else:
            assert len(callbacks) == callback_count, (label, callbacks)
        assert len(proxy_accepts) - accepts_before == int(expect_proxy), (label, proxy_accepts)
        after = counters()
        if preserve_reserved:
            assert after['auth-bit-leaked'] > before['auth-bit-leaked'], (label, before, after)
        else:
            assert after['auth-bit-leaked'] == before['auth-bit-leaked'], (label, before, after)
        assert after['other-priority-preserved'] > before['other-priority-preserved'], (label, before, after)
        assert after['other-mark-preserved'] > before['other-mark-preserved'], (label, before, after)
        reserved = 'preserved outside scope' if preserve_reserved else 'cleared'
        print(f'{label}: PASS; original peer retained, reserved bit {reserved}, other priority and mark preserved')

    with tempfile.TemporaryDirectory(prefix='exitlag-authorization-test-') as work:
        work = Path(work)
        log, token, ready = work / 'netd.log', work / 'token', work / 'peer.ready'
        try:
            checked(ip, 'netns', 'add', namespace)
            namespace_created = True
            checked(ip, 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', peer_if)
            link_created = True
            checked(ip, 'link', 'set', peer_if, 'netns', namespace)
            checked(ip, 'addr', 'add', HOST_V4 + '/24', 'dev', host_if)
            checked(ip, '-6', 'addr', 'add', HOST_V6 + '/64', 'dev', host_if, 'nodad')
            checked(ip, 'link', 'set', host_if, 'up')
            checked(ip, 'netns', 'exec', namespace, ip, 'link', 'set', 'lo', 'up')
            checked(ip, 'netns', 'exec', namespace, ip, 'addr', 'add', PEER_V4 + '/24', 'dev', peer_if)
            checked(ip, 'netns', 'exec', namespace, ip, '-6', 'addr', 'add', PEER_V6 + '/64', 'dev', peer_if, 'nodad')
            checked(ip, 'netns', 'exec', namespace, ip, 'link', 'set', peer_if, 'up')
            server = subprocess.Popen([
                ip, 'netns', 'exec', namespace, sys.executable, str(Path(__file__).resolve()),
                '--echo-server', PEER_V4, PEER_V6, str(ready),
            ])
            wait_for_log(ready, '{', server)
            peer_ports = json.loads(ready.read_text())
            for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                listener = socket.socket(family)
                listeners.append(listener)
                listener.bind((address, 0))
                listener.listen(16)
                listener.settimeout(.2)
                proxies[family] = (address, listener.getsockname()[1])
                worker = threading.Thread(target=proxy_worker, args=(listener, family), daemon=True)
                workers.append(worker)
                worker.start()

            install_table('any')

            # Loopback never reaches NFQUEUE. Even a premarked packet must not
            # turn a stale map entry into authorization for a fresh connection.
            loopbacks = {}
            for family, address in ((socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')):
                original = socket.socket(family)
                listeners.append(original)
                original.bind((address, 0))
                original.listen(4)
                original.settimeout(.2)

                def original_worker(listener=original):
                    try:
                        while not stopping.is_set():
                            try:
                                connection, _peer = listener.accept()
                            except socket.timeout:
                                continue
                            with connection:
                                connection.settimeout(3)
                                connection.sendall(b'ORIGINAL:' + receive_exact(connection, 4))
                    except Exception as error:
                        if not stopping.is_set():
                            errors.put(error)

                worker = threading.Thread(target=original_worker, daemon=True)
                workers.append(worker)
                worker.start()
                remote = (address, original.getsockname()[1])
                loopbacks[family] = remote
                probe(family, remote, f'IPv{4 if family == socket.AF_INET else 6} stale loopback')
                probe(family, remote, f'IPv{4 if family == socket.AF_INET else 6} forged loopback priority', forged=True)

            families = ((socket.AF_INET, PEER_V4), (socket.AF_INET6, PEER_V6))
            for family, address in families:
                probe(family, (address, peer_ports[str(family)]),
                      f'IPv{4 if family == socket.AF_INET else 6} helper absent', forged=True)

            helper_env = os.environ.copy()
            helper_env.pop('EXITLAG_IDENTITY_MAP', None)
            ipc_port = available_port()
            helper = subprocess.Popen([
                str(helper_binary), '--queue', str(queue_number), '--port', str(ipc_port),
                '--timeout-ms', '1000', '--apply-tcp', '--peer-uid', str(os.geteuid()),
                '--token-file', str(token), '--log', str(log),
            ], env=helper_env)
            wait_for_log(log, f'bound NFQUEUE {queue_number}', helper)
            for family, address in families:
                probe(family, (address, peer_ports[str(family)]),
                      f'IPv{4 if family == socket.AF_INET else 6} no authenticated shim', forged=True)

            shim = authenticate(ipc_port, token, helper)
            shim.settimeout(8)
            shim_thread = threading.Thread(target=mock_shim, daemon=True)
            shim_thread.start()
            if not heartbeat.wait(5):
                if not errors.empty():
                    raise errors.get_nowait()
                raise RuntimeError('no synthetic peer heartbeat')
            for selected in ('unchanged', 'no-handler', 'invalid', 'valid'):
                mode['value'] = selected
                for family, address in families:
                    probe(family, (address, peer_ports[str(family)]),
                          f'IPv{4 if family == socket.AF_INET else 6} mock {selected}',
                          forged=True, expect_proxy=selected == 'valid', expect_callback=True)

            # Out-of-scope traffic retains all priority/mark bits. A stale map
            # plus an inherited reserved bit must still not select our DNAT.
            shim_stopping.set()
            close_socket(shim)
            shim = None
            shim_thread.join(4)
            if shim_thread.is_alive():
                raise RuntimeError('synthetic peer did not stop before scope transition')
            stop_process(helper)
            helper = None
            checked(str(ROOT / 'backend/nft-teardown.sh'), stdout=subprocess.DEVNULL)
            table_installed = False
            install_table('203.0.113.99')
            for family, address in families:
                version = 4 if family == socket.AF_INET else 6
                probe(family, loopbacks[family], f'IPv{version} loopback outside destination scope',
                      forged=True, preserve_reserved=True)
                probe(family, (address, peer_ports[str(family)]),
                      f'IPv{version} peer outside destination scope', forged=True, preserve_reserved=True)
        finally:
            stopping.set()
            close_socket(shim)
            cleanup_errors = []
            for process in (helper, server):
                try:
                    stop_process(process)
                except Exception as error:
                    cleanup_errors.append(str(error))
            for listener in listeners:
                listener.close()
            for worker in [shim_thread, *workers]:
                if worker is not None:
                    worker.join(4)
                    if worker.is_alive():
                        cleanup_errors.append('authorization worker did not stop')
            if table_installed:
                try:
                    checked(str(ROOT / 'backend/nft-teardown.sh'), stdout=subprocess.DEVNULL)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if namespace_created:
                try:
                    checked(ip, 'netns', 'delete', namespace)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if link_created:
                subprocess.run([ip, 'link', 'delete', host_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if token.exists():
                cleanup_errors.append('helper token remains')
            if table_installed and table_exists(nft):
                cleanup_errors.append('owned nft table remains')
            if cleanup_errors:
                raise RuntimeError('authorization cleanup failed: ' + '; '.join(cleanup_errors))
    print('stale-map TCP authorization: PASS; IPv4/IPv6 and cleanup; cached conntrack NOT TESTED')
    return 0


if __name__ == '__main__':
    raise SystemExit(run_main(main))
