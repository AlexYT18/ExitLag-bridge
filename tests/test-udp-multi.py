#!/usr/bin/env python3
"""Real UDP/NFQUEUE regression with explicitly synthetic routing callbacks.

Run only through tests/run-isolated.sh. No account, official ExitLag routing
decision, relay infrastructure or game compatibility is represented here.
"""
import json
import os
from pathlib import Path
import queue
import secrets
import signal
import select
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from integration_support import (
    authenticate, available_port, checked, close_socket, receive_frame,
    require_isolation, required_tool, respond_to_heartbeat, run_main,
    send_frame, stop_process, table_exists, wait_for_log,
)


ROOT = Path(__file__).resolve().parent.parent
CREATED, CREATED_REPLY, CONNECT, CONNECT_REPLY = 0x40, 0x41, 0x42, 0x43
DATAGRAM, DATAGRAM_REPLY, POST, CLOSED, CLOSED_REPLY = 0x44, 0x45, 0x46, 0x48, 0x49
POST_SEND, POST_RECEIVE = 1, 2
HOST = {4: '198.18.80.1', 6: '2001:db8:80::1'}
PEER = {4: '198.18.80.2', 6: '2001:db8:80::2'}
LIFECYCLE = struct.Struct('<QQIH28s')
LIFECYCLE_REPLY = struct.Struct('<QIIH28sB3s')
CONNECT_REQUEST = struct.Struct('<QQIIH28s28s')
CONNECT_RESPONSE = struct.Struct('<QIII28sBB2s')
DATAGRAM_REQUEST = struct.Struct('<QQIBBH28s28sIII')
DATAGRAM_RESPONSE = struct.Struct('<QIIIIBBBB')
POST_HEADER = struct.Struct('<QQIi28sIII')
STATE, SET_FLOWCTL = 0x47, 6
STATE_HEADER = struct.Struct('<QQIiII')


def family_for(version):
    return socket.AF_INET if version == 4 else socket.AF_INET6


def wire_address(version, remote):
    result = bytearray(28)
    struct.pack_into('<H', result, 0, 2 if version == 4 else 23)
    struct.pack_into('!H', result, 2, remote[1])
    address = socket.inet_pton(family_for(version), remote[0])
    offset = 4 if version == 4 else 8
    result[offset:offset + len(address)] = address
    return bytes(result)


def from_wire(address):
    family = struct.unpack_from('<H', address)[0]
    version = 4 if family == 2 else 6 if family == 23 else None
    if version is None:
        raise RuntimeError(f'unsupported synthetic address family {family}')
    offset, size = (4, 4) if version == 4 else (8, 16)
    return version, (socket.inet_ntop(family_for(version), address[offset:offset + size]),
                     struct.unpack_from('!H', address, 2)[0])


def echo_server(arguments):
    ready, records = map(Path, arguments)
    servers, published = [], {}
    try:
        with selectors.DefaultSelector() as poller:
            for version in (4, 6):
                published[str(version)] = {'original': [], 'relay': None}
                for role in ('original-0', 'original-1', 'relay'):
                    server = socket.socket(family_for(version), socket.SOCK_DGRAM)
                    servers.append(server)
                    server.bind((PEER[version], 0))
                    poller.register(server, selectors.EVENT_READ, (version, role))
                    port = server.getsockname()[1]
                    if role == 'relay':
                        published[str(version)]['relay'] = port
                    else:
                        published[str(version)]['original'].append(port)
            ready.write_text(json.dumps(published) + '\n')
            while True:
                for key, _events in poller.select(20):
                    data, source = key.fileobj.recvfrom(65535)
                    version, role = key.data
                    with records.open('a') as log:
                        log.write(json.dumps({'version': version, 'role': role,
                                              'payload': data.hex(), 'source': source[:2]}) + '\n')
                    prefix = b'RELAY:' if role == 'relay' else b'ORIGINAL:'
                    key.fileobj.sendto(prefix + data, source)
    finally:
        for server in servers:
            server.close()


class Client:
    def __init__(self, version, port=0, *, reuse=False, local_address=None):
        self.version = version
        self.process = subprocess.Popen(
            [sys.executable, str(ROOT / 'tests/udp-multi-client.py'), str(version),
             local_address or HOST[version], str(port), *(['reuse'] if reuse else [])],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1)
        ready = self.read()
        self.pid, self.local = ready['pid'], tuple(ready['local'])

    def read(self):
        if not select.select([self.process.stdout], [], [], 6)[0]:
            raise RuntimeError('private UDP client response timed out')
        line = self.process.stdout.readline()
        if not line:
            try:
                self.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
            detail = self.process.stderr.read(4096) if self.process.poll() is not None else ''
            raise RuntimeError(f'private UDP client exited without a response: {detail}')
        return json.loads(line)

    def begin(self, remote, payload, connected=False, *, notify_sent=False, mark=0, priority=0):
        self.process.stdin.write(json.dumps({'action': 'request', 'remote': remote,
                                            'payload': payload.hex(), 'connected': connected,
                                            'notify_sent': notify_sent, 'mark': mark,
                                            'priority': priority}) + '\n')
        self.process.stdin.flush()

    def finish(self, remote, expected, connected=False):
        result = self.read()
        if bytes.fromhex(result['payload']) != expected or tuple(result['peer']) != remote:
            raise AssertionError(f'UDP application reply/source mismatch: {result}, expected {expected!r}/{remote}')
        if result['pid'] != self.pid or tuple(result['local']) != self.local:
            raise AssertionError('UDP child identity/local endpoint changed')
        if connected and tuple(result['connected_peer']) != remote:
            raise AssertionError('connected UDP original peer semantics changed')
        return result

    def batch(self, requests):
        self.process.stdin.write(json.dumps({'action': 'batch', 'requests': [
            {'remote': remote, 'payload': payload.hex()} for remote, payload in requests]}) + '\n')
        self.process.stdin.flush()
        result = self.read()
        if result['pid'] != self.pid or tuple(result['local']) != self.local:
            raise AssertionError('UDP batch child identity/local endpoint changed')
        return {(tuple(reply['peer']), bytes.fromhex(reply['payload']))
                for reply in result['responses']}

    def close(self):
        if self.process.poll() is None:
            try:
                self.process.stdin.write('{"action":"close"}\n')
                self.process.stdin.flush()
                self.process.stdin.close()
                self.process.wait(timeout=3)
            finally:
                stop_process(self.process)
        for stream in (self.process.stdout, self.process.stderr):
            stream.close()


class MockPeer:
    def __init__(self, connection, ports, state, records, errors, phase):
        self.connection, self.ports, self.state = connection, ports, state
        self.records, self.errors, self.phase = records, errors, phase
        self.endpoints, self.routes = {}, {}
        self.stopping, self.heartbeat = threading.Event(), threading.Event()
        self.worker = threading.Thread(target=self.run, daemon=True)
        self.worker.start()

    def post(self, tag, endpoint, api, remote, data, *, status=0, options=b''):
        body = POST_HEADER.pack(tag, endpoint, api, status, remote, 0, len(options), len(data))
        send_frame(self.connection, POST, body + options + data)

    def run(self):
        try:
            while not self.stopping.is_set():
                kind, body = receive_frame(self.connection)
                if respond_to_heartbeat(self.connection, kind, body):
                    self.heartbeat.set()
                    continue
                if kind in (CREATED, CLOSED):
                    tag, endpoint, pid, family, local = LIFECYCLE.unpack(body)
                    version, decoded_local = from_wire(local)
                    if pid not in self.state['pids'] or family != (2 if version == 4 else 23):
                        raise RuntimeError(f'unexpected UDP lifecycle identity {pid}/{family}')
                    self.records.append({'phase': self.phase, 'kind': kind, 'id': endpoint,
                                         'pid': pid, 'local': decoded_local, 'version': version})
                    if kind == CREATED:
                        if endpoint in self.endpoints:
                            raise RuntimeError('duplicate udpCreated in one shim session')
                        self.endpoints[endpoint] = (pid, version, local)
                        if self.state['mode'] == 'persistent-control':
                            # A valid control in udpCreated must remain in
                            # force after that RPC's counters have been reset.
                            send_frame(self.connection, STATE,
                                       STATE_HEADER.pack(tag, endpoint, SET_FLOWCTL, 0, 1, 0))
                    else:
                        if self.endpoints.pop(endpoint, None) != (pid, version, local):
                            raise RuntimeError('udpClosed arrived without its matching lifecycle/owner')
                    send_frame(self.connection, CREATED_REPLY if kind == CREATED else CLOSED_REPLY,
                               LIFECYCLE_REPLY.pack(tag, 0, pid, family, local, 0, bytes(3)))
                    continue
                if kind == CONNECT:
                    tag, endpoint, pid, flag, family, local, remote = CONNECT_REQUEST.unpack(body)
                    if self.endpoints.get(endpoint) != (pid, 4 if family == 2 else 6, local):
                        raise RuntimeError('udpConnectRequest arrived before matching udpCreated')
                    self.records.append({'phase': self.phase, 'kind': kind, 'id': endpoint, 'pid': pid})
                    send_frame(self.connection, CONNECT_REPLY,
                               CONNECT_RESPONSE.pack(tag, 0, pid, flag, remote, 0, 0, bytes(2)))
                    continue
                if kind != DATAGRAM or len(body) < DATAGRAM_REQUEST.size:
                    raise RuntimeError(f'unexpected mock UDP message {kind:#x}/{len(body)}')
                tag, endpoint, pid, direction, reserved, family, local, remote, flags, options_len, data_len = DATAGRAM_REQUEST.unpack_from(body)
                version = 4 if family == 2 else 6 if family == 23 else None
                if (version is None or direction not in (1, 2) or reserved or
                        len(body) != DATAGRAM_REQUEST.size + options_len + data_len or
                        self.endpoints.get(endpoint) != (pid, version, local)):
                    raise RuntimeError('invalid UDP datagram or missing fresh lifecycle')
                if pid not in self.state['pids']:
                    raise RuntimeError('unrelated process reached UDP callbacks')
                data = body[DATAGRAM_REQUEST.size + options_len:]
                mode = self.state['mode']
                record = {'phase': self.phase, 'kind': kind, 'id': endpoint, 'pid': pid,
                          'direction': direction, 'mode': mode, 'payload': data.hex(),
                          'remote': from_wire(remote)[1]}
                self.records.append(record)
                target, posted = remote, data
                api = POST_SEND if direction == 2 else POST_RECEIVE
                if direction == 2 and mode in ('rewrite', 'local-rewrite', 'collision'):
                    self.routes[(endpoint, b'RELAY:wire:' + data)] = (remote, data)
                    relay = (('127.0.0.1' if version == 4 else '::1',
                              self.ports[str(version)]['local-relay']) if mode == 'local-rewrite'
                             else (PEER[version], self.ports[str(version)]['relay']))
                    target = wire_address(version, relay)
                    posted = b'wire:' + data
                elif direction == 1 and mode == 'collision':
                    if not data.startswith(b'ORIGINAL:'):
                        raise RuntimeError('ambiguous cross-endpoint relay binding was executed')
                elif direction == 1 and mode in ('rewrite', 'local-rewrite'):
                    if (endpoint, data) not in self.routes:
                        raise RuntimeError('relay receive has no matching outbound flow')
                    target, original = self.routes.pop((endpoint, data))
                    if data != b'RELAY:wire:' + original:
                        raise RuntimeError(f'relay wire payload not preserved: {data!r}')
                    posted = b'decoded:' + original
                post_tag, status, options = tag, 0, b''
                if direction == 2:
                    if mode == 'wrong-tag': post_tag += 100000
                    elif mode == 'wrong-endpoint': endpoint += 100000
                    elif mode == 'options': options = b'unsupported'
                    elif mode == 'status': status = -1
                    elif mode == 'direction': api = POST_RECEIVE
                    elif mode == 'zero-port':
                        target = wire_address(version, (PEER[version], 0))
                    elif mode == 'wrong-family':
                        target = wire_address(6 if version == 4 else 4,
                                              (PEER[6 if version == 4 else 4], 49000))
                    elif mode == 'timeout':
                        # A live authenticated peer deliberately stops replying.
                        # The bounded daemon transaction must accept the original.
                        continue
                elif mode == 'bad-receive':
                    post_tag += 100000
                    posted = b'this invalid receive post must not reach the game'
                elif direction == 1 and mode == 'receive-empty':
                    posted = b''
                self.post(post_tag, endpoint, api, target, posted, status=status, options=options)
                if direction == 2 and mode == 'duplicate':
                    self.post(tag, endpoint, api, target, posted)
                # Deliberately lie about duplicate count to ensure the backend
                # validates actual nested frames, not only this summary field.
                send_frame(self.connection, DATAGRAM_REPLY,
                           DATAGRAM_RESPONSE.pack(tag, 0, 1, 0, 0, 0, 0, 0, 0))
        except Exception as error:
            if not self.stopping.is_set() and self.state['mode'] != 'timeout':
                self.errors.put(error)

    def stop(self):
        self.stopping.set()
        close_socket(self.connection)
        self.worker.join(6)
        if self.worker.is_alive():
            raise RuntimeError('synthetic UDP callback worker did not stop')


def main():
    require_isolation()  # Before sockets, subprocesses or firewall mutations.
    if sys.argv[1:2] == ['--echo-server']:
        if len(sys.argv) != 4:
            raise RuntimeError('invalid private UDP echo-server arguments')
        return echo_server(sys.argv[2:])
    if sys.argv[1:]:
        raise RuntimeError('run test-udp-multi.py through tests/run-isolated.sh')
    nft, ip = required_tool('nft'), required_tool('ip')
    if table_exists(nft):
        raise RuntimeError('refusing to touch pre-existing table inet exitlag')
    suffix = secrets.token_hex(3)
    namespace, host_if, peer_if = 'exlumm-' + suffix, 'exlummh' + suffix, 'exlummp' + suffix
    namespace_created = link_created = table_installed = False
    helper = server = mock_peer = None
    clients, records = [], []
    local_proxy_sockets, local_proxy_workers = [], []
    local_proxy_records = queue.Queue()
    local_proxy_stopping = threading.Event()
    errors = queue.Queue()
    state = {'mode': 'identity', 'pids': set()}
    tcp_queue = 12000 + os.getpid() % 1000 * 2
    udp_queue = tcp_queue + 1
    ipc_port = available_port()
    passed = 0

    def check_errors():
        if not errors.empty():
            raise errors.get_nowait()

    def marked_packets():
        result = json.loads(checked(nft, '-j', 'list', 'chain', 'inet', 'exitlag',
                                    'output_udp_observe', capture_output=True, text=True).stdout)
        total = 0
        for item in result['nftables']:
            expressions = item.get('rule', {}).get('expr', [])
            marked = any(expression.get('match', {}).get('left') == {'meta': {'key': 'mark'}}
                         and expression['match'].get('right') == 0x584c0001 for expression in expressions)
            if marked:
                total += sum(expression['counter']['packets'] for expression in expressions if 'counter' in expression)
        return total

    def metadata_counters(chain):
        result = json.loads(checked(nft, '-j', 'list', 'chain', 'inet', 'exitlag', chain,
                                    capture_output=True, text=True).stdout)
        return {rule['comment']: sum(expression['counter']['packets']
                                    for expression in rule['expr'] if 'counter' in expression)
                for item in result['nftables'] if (rule := item.get('rule', {})).get('comment')}

    def client(version, port=0, *, reuse=False, local_address=None, authorized=True):
        result = Client(version, port, reuse=reuse, local_address=local_address)
        clients.append(result)
        if authorized:
            state['pids'].add(result.pid)
        return result

    def record_for(pid, payload, phase):
        matching = [r for r in records if r['phase'] == phase and r['kind'] == DATAGRAM
                    and r['pid'] == pid and r['direction'] == 2 and r['payload'] == payload.hex()]
        if len(matching) != 1:
            raise AssertionError(f'expected one outgoing callback for {pid}/{payload!r}, got {matching}')
        return matching[0]

    with tempfile.TemporaryDirectory(prefix='exitlag-udp-multi-') as work:
        work = Path(work)
        ready, server_records = work / 'server.ready', work / 'server.jsonl'
        log, token = work / 'netd.log', work / 'token'
        try:
            checked(ip, 'netns', 'add', namespace); namespace_created = True
            checked(ip, 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', peer_if); link_created = True
            checked(ip, 'link', 'set', peer_if, 'netns', namespace)
            for version in (4, 6):
                address_args = ['-6'] if version == 6 else []
                prefix = '/64' if version == 6 else '/24'
                checked(ip, *address_args, 'addr', 'add', HOST[version] + prefix, 'dev', host_if,
                        *(['nodad'] if version == 6 else []))
            checked(ip, 'link', 'set', host_if, 'up')
            checked(ip, 'netns', 'exec', namespace, ip, 'link', 'set', 'lo', 'up')
            for version in (4, 6):
                checked(ip, 'netns', 'exec', namespace, ip, *(['-6'] if version == 6 else []),
                        'addr', 'add', PEER[version] + ('/64' if version == 6 else '/24'), 'dev', peer_if,
                        *(['nodad'] if version == 6 else []))
            checked(ip, 'netns', 'exec', namespace, ip, 'link', 'set', peer_if, 'up')
            server = subprocess.Popen([ip, 'netns', 'exec', namespace, sys.executable, str(Path(__file__).resolve()),
                                       '--echo-server', str(ready), str(server_records)])
            wait_for_log(ready, '{', server)
            ports = json.loads(ready.read_text())
            for version in (4, 6):
                local_proxy = socket.socket(family_for(version), socket.SOCK_DGRAM)
                local_proxy.bind(('127.0.0.1' if version == 4 else '::1', 0))
                local_proxy.settimeout(.2)
                local_proxy_sockets.append(local_proxy)
                ports[str(version)]['local-relay'] = local_proxy.getsockname()[1]

                def local_proxy_echo(proxy=local_proxy, address_family=version):
                    try:
                        while not local_proxy_stopping.is_set():
                            try:
                                data, source = proxy.recvfrom(65535)
                            except socket.timeout:
                                continue
                            local_proxy_records.put((address_family, data, source[:2]))
                            proxy.sendto(b'RELAY:' + data, source)
                    except OSError as error:
                        if not local_proxy_stopping.is_set():
                            errors.put(error)

                proxy_worker = threading.Thread(target=local_proxy_echo, daemon=True)
                local_proxy_workers.append(proxy_worker)
                proxy_worker.start()
            env = os.environ.copy()
            env.update(QUEUE_NUM=str(tcp_queue), TEST_DEST='203.0.113.1', UDP_QUEUE_NUM=str(udp_queue),
                       UDP_TEST_DEST='any', UDP_TEST_PORT='1-65535', ENABLE_UDP_OBSERVE='1',
                       ENABLE_UDP_STEER='1', ENABLE_UDP_MULTI='1')
            env.pop('EXL_USER_UID', None)
            checked(str(ROOT / 'backend/nft-setup.sh'), env=env, stdout=subprocess.DEVNULL)
            table_installed = True
            checked(nft, '-f', '-', text=True, input='''
add chain inet exitlag test_udp_metadata_output { type filter hook output priority -9; policy accept; }
add chain inet exitlag test_udp_metadata_input_mark { type filter hook input priority -20; policy accept; }
add chain inet exitlag test_udp_metadata_input { type filter hook input priority -9; policy accept; }
''')

            def request(owner, remote, payload, *, mode='identity', connected=False,
                        callbacks=True, expected=None, mark=0, priority=0):
                nonlocal passed
                state['mode'] = mode
                before = marked_packets()
                owner.begin(remote, payload, connected, mark=mark, priority=priority)
                if expected is None:
                    expected = b'decoded:' + payload if mode in ('rewrite', 'local-rewrite') else b'ORIGINAL:' + payload
                owner.finish(remote, expected, connected)
                check_errors()
                after = marked_packets()
                active = callbacks and mode in ('identity', 'rewrite', 'bad-receive', 'receive-empty')
                if after - before != int(active):
                    raise AssertionError(f'wrong raw replacement count for {mode}: {before}->{after}')
                if callbacks:
                    record_for(owner.pid, payload, mock_peer.phase)
                else:
                    forbidden = {payload.hex(), (b'ORIGINAL:' + payload).hex()}
                    assert not any(r['kind'] == DATAGRAM and r['payload'] in forbidden
                                   for r in records), 'out-of-scope datagram reached callbacks'
                passed += 1
                print(f'IPv{owner.version} {mode} pid={owner.pid}: PASS; bidirectional bytes/source and replacement count')

            # Queue bypass and unauthenticated helper are direct, never active.
            initial = client(4)
            remote4 = (PEER[4], ports['4']['original'][0])
            request(initial, remote4, b'no-helper', callbacks=False)
            helper_env = os.environ.copy(); helper_env.pop('EXITLAG_IDENTITY_MAP', None)
            helper = subprocess.Popen([
                str(ROOT / 'backend/exitlag-netd'), '--queue', str(tcp_queue), '--udp-queue', str(udp_queue),
                '--port', str(ipc_port), '--apply-udp', '--udp-multi', '--allow-remote-redirect',
                '--timeout-ms', '300', '--peer-uid', str(os.geteuid()), '--token-file', str(token), '--log', str(log),
            ], env=helper_env)
            wait_for_log(log, f'bound UDP NFQUEUE {udp_queue}', helper)
            request(initial, remote4, b'no-shim', callbacks=False)
            peer = authenticate(ipc_port, token, helper); peer.settimeout(8)
            mock_peer = MockPeer(peer, ports, state, records, errors, 1)
            if not mock_peer.heartbeat.wait(5):
                check_errors(); raise RuntimeError('no synthetic UDP heartbeat')
            request(initial, remote4, b'now-authenticated')

            persistent, controlled_clients = [], []
            for version in (4, 6):
                first, second = client(version), client(version)
                persistent.append(first)
                original = (PEER[version], ports[str(version)]['original'][0])
                other = (PEER[version], ports[str(version)]['original'][1])
                state['mode'] = 'identity'
                before = marked_packets()
                first_payload, second_payload = f'parallel-{version}-one'.encode(), f'parallel-{version}-two'.encode()
                first.begin(original, first_payload)
                second.begin(other, second_payload, connected=True)
                first.finish(original, b'ORIGINAL:' + first_payload)
                second.finish(other, b'ORIGINAL:' + second_payload, connected=True)
                check_errors()
                assert marked_packets() - before == 2
                one = record_for(first.pid, first_payload, 1)
                two = record_for(second.pid, second_payload, 1)
                assert one['id'] != two['id'], (one, two)
                passed += 1
                print(f'IPv{version} simultaneous distinct process/socket attribution: PASS')
                request(first, other, f'dynamic-{version}'.encode())
                request(first, original, f'route-{version}'.encode(), mode='rewrite')
                request(second, other, f'connected-route-{version}'.encode(), mode='rewrite', connected=True)
                local_owner = client(version)
                local_payload = f'loopback-proxy-{version}'.encode()
                # oif lo accepts before the mark counter. Actual proxy bytes,
                # connected getpeername and restored recvfrom source, rather
                # than this counter, demonstrate the local replacement path.
                request(local_owner, original, local_payload, mode='local-rewrite', connected=True)
                proxy_version, proxy_payload, proxy_source = local_proxy_records.get(timeout=1)
                assert (proxy_version, proxy_payload, tuple(proxy_source)) == (
                    version, b'wire:' + local_payload, local_owner.local)
                print(f'IPv{version} ordinary loopback proxy rewrite restores connected UDP source: PASS')
                state['mode'] = 'rewrite'
                before = marked_packets()
                batches = [(original, f'inflight-{version}-one'.encode()),
                           (other, f'inflight-{version}-two'.encode())]
                replies = first.batch(batches)
                assert replies == {(remote, b'decoded:' + payload) for remote, payload in batches}, replies
                check_errors()
                assert marked_packets() - before == 2
                identities = [record_for(first.pid, payload, 1)['id'] for _remote, payload in batches]
                assert identities[0] == identities[1]
                passed += 1
                print(f'IPv{version} one unconnected socket with two in-flight relay remotes: PASS')
                request(first, original, b'')
                request(first, original, f'empty-receive-{version}'.encode(),
                        mode='receive-empty', expected=b'')
                for invalid in ('wrong-tag', 'wrong-endpoint', 'duplicate', 'options', 'status',
                                'direction', 'zero-port', 'wrong-family', 'bad-receive'):
                    request(first, original, f'{invalid}-{version}'.encode(), mode=invalid)

                # SO_REUSEADDR permits different connected sockets to share
                # a local address/port. Their original remotes disambiguate
                # attribution, but one common relay peer would not. The
                # second conflicting redirect must fail open before raw send.
                shared_first = client(version, reuse=True)
                request(shared_first, original, f'shared-first-{version}'.encode(),
                        mode='rewrite', connected=True)
                shared_second = client(version, shared_first.local[1], reuse=True)
                collision_payload = f'shared-collision-{version}'.encode()
                request(shared_second, other, collision_payload, mode='collision', connected=True)
                shared_one = record_for(shared_first.pid, f'shared-first-{version}'.encode(), 1)
                shared_two = record_for(shared_second.pid, collision_payload, 1)
                assert shared_one['id'] != shared_two['id']
                request(shared_first, original, f'shared-still-routed-{version}'.encode(),
                        mode='rewrite', connected=True)
                print(f'IPv{version} shared-local cross-process relay collision fails open: PASS')

                # Loopback remains outside capture. This extra process is not
                # authorized by the mock and must produce no callback at all.
                loopback = '127.0.0.1' if version == 4 else '::1'
                with socket.socket(family_for(version), socket.SOCK_DGRAM) as control_server:
                    control_server.bind((loopback, 0))
                    control_server.settimeout(4)
                    def control_echo():
                        try:
                            payload, source = control_server.recvfrom(65535)
                            control_server.sendto(b'ORIGINAL:' + payload, source)
                        except Exception as error:
                            errors.put(error)
                    control_worker = threading.Thread(target=control_echo, daemon=True)
                    control_worker.start()
                    control = client(version, local_address=loopback, authorized=False)
                    request(control, (loopback, control_server.getsockname()[1]),
                            f'untouched-control-{version}'.encode(), callbacks=False)
                    control_worker.join(5)
                    if control_worker.is_alive():
                        raise RuntimeError('private loopback control server did not stop')
                    check_errors()

                # Do not wait for sweep: a different PID immediately reuses the
                # closed socket's local port, reproducing the historical bug.
                old_port, old_pid = second.local[1], second.pid
                old_id = two['id']
                second.close()
                rebound = client(version, old_port)
                reuse_payload = f'rebound-{version}'.encode()
                request(rebound, original, reuse_payload)
                fresh = record_for(rebound.pid, reuse_payload, 1)
                assert rebound.pid != old_pid and fresh['id'] != old_id, (two, fresh)
                print(f'IPv{version} immediate local-port reuse has fresh PID and endpoint: PASS')

                controlled = client(version)
                controlled_clients.append(controlled)
                request(controlled, original, f'created-control-{version}'.encode(),
                        mode='persistent-control')
                request(controlled, other, f'created-control-persists-{version}'.encode(),
                        mode='persistent-control')
                print(f'IPv{version} lifecycle control remains fail-open across datagrams: PASS')

                # These test-only rules observe metadata after the production
                # queue. Mark the reply too: the native guard is packet-level,
                # and an ordinary unmarked reply is a separate supported event.
                marked_owner, priority_owner = client(version), client(version)
                address_type = 'ip' if version == 4 else 'ip6'
                mark, priority = 0x12340000, 0x00020004
                marked_out = (f'{address_type} saddr {HOST[version]} udp sport {marked_owner.local[1]} '
                              f'{address_type} daddr {original[0]} udp dport {original[1]}')
                marked_in = (f'{address_type} saddr {original[0]} udp sport {original[1]} '
                             f'{address_type} daddr {HOST[version]} udp dport {marked_owner.local[1]}')
                priority_out = (f'{address_type} saddr {HOST[version]} udp sport {priority_owner.local[1]} '
                                f'{address_type} daddr {original[0]} udp dport {original[1]}')
                checked(nft, '-f', '-', text=True, input=f'''
add rule inet exitlag test_udp_metadata_output {marked_out} meta mark 0x{mark:x} counter comment "fwmark-out-{version}"
add rule inet exitlag test_udp_metadata_input_mark {marked_in} meta mark set 0x{mark:x}
add rule inet exitlag test_udp_metadata_input {marked_in} meta mark 0x{mark:x} counter comment "fwmark-in-{version}"
add rule inet exitlag test_udp_metadata_output {priority_out} meta mark 0x584c0001 meta priority 2:4 counter comment "priority-preserved-{version}"
add rule inet exitlag test_udp_metadata_output {priority_out} meta mark 0x584c0001 meta priority != 2:4 counter comment "priority-wrong-{version}"
''')
                request(marked_owner, original, f'packet-fwmark-{version}'.encode(),
                        callbacks=False, mark=mark)
                assert metadata_counters('test_udp_metadata_output')[f'fwmark-out-{version}'] == 1
                assert metadata_counters('test_udp_metadata_input')[f'fwmark-in-{version}'] == 1
                request(priority_owner, original, f'packet-priority-{version}'.encode(), priority=priority)
                priorities = metadata_counters('test_udp_metadata_output')
                assert priorities[f'priority-preserved-{version}'] == 1, priorities
                assert priorities[f'priority-wrong-{version}'] == 0, priorities
                print(f'IPv{version} nonzero packet fwmark fails open and 32-bit raw priority is preserved: PASS')

            mock_peer.stop(); mock_peer = None
            # A replacement shim must receive lifecycle before datagrams even
            # though the game sockets themselves have stayed open.
            peer = authenticate(ipc_port, token, helper); peer.settimeout(8)
            mock_peer = MockPeer(peer, ports, state, records, errors, 2)
            if not mock_peer.heartbeat.wait(5):
                check_errors(); raise RuntimeError('no reconnected synthetic UDP heartbeat')
            for owner in persistent + controlled_clients:
                remote = (PEER[owner.version], ports[str(owner.version)]['original'][0])
                payload = f'reconnected-{owner.version}'.encode()
                request(owner, remote, payload)
                current = record_for(owner.pid, payload, 2)
                assert any(r['phase'] == 2 and r['kind'] == CREATED and r['id'] == current['id'] for r in records)
                assert current['id'] not in {r['id'] for r in records if r['phase'] == 1}, current
            # A timed-out callback must fail open, invalidate that session, and
            # allow a fresh authenticated peer to recreate the endpoint.
            request(persistent[0], remote4, b'callback-timeout', mode='timeout')
            mock_peer.stop(); mock_peer = None
            peer = authenticate(ipc_port, token, helper); peer.settimeout(8)
            mock_peer = MockPeer(peer, ports, state, records, errors, 3)
            if not mock_peer.heartbeat.wait(5):
                check_errors(); raise RuntimeError('no post-timeout synthetic UDP heartbeat')
            request(persistent[0], remote4, b'post-timeout-reconnected')
            current = record_for(persistent[0].pid, b'post-timeout-reconnected', 3)
            assert current['id'] not in {r['id'] for r in records if r['phase'] in (1, 2)}, current

            # Force the same poll round to observe a queued UDP packet and an
            # IPC PONG. The packet RPC consumes the PONG; reading again from
            # the stale poll snapshot must not disconnect this live session.
            state['mode'] = 'identity'
            mock_peer.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            time.sleep(.05)
            paused = False
            payload = b'queued-packet-plus-ready-pong'
            before = marked_packets()
            try:
                os.kill(helper.pid, signal.SIGSTOP)
                paused = True
                persistent[0].begin(remote4, payload, notify_sent=True)
                sent = persistent[0].read()
                # UDP sendto returns after netfilter has taken ownership of
                # the queued packet. This acknowledgement needs no access to
                # the root-owned global /proc NFQUEUE statistics file.
                assert sent == {'event': 'sent', 'pid': persistent[0].pid}, sent
                send_frame(mock_peer.connection, 0x0004)
                os.kill(helper.pid, signal.SIGCONT)
                paused = False
                persistent[0].finish(remote4, b'ORIGINAL:' + payload)
            finally:
                if paused and helper.poll() is None:
                    os.kill(helper.pid, signal.SIGCONT)
            check_errors()
            assert marked_packets() - before == 1
            record_for(persistent[0].pid, payload, 3)
            passed += 1
            time.sleep(.3)
            check_errors()
            request(persistent[0], remote4, b'after-simultaneous-pong')
            print('simultaneous NFQUEUE packet and PONG preserve the authenticated session: PASS')
            check_errors()
            assert any(json.loads(line)['role'] == 'relay' for line in server_records.read_text().splitlines())
            print('new shim session lifecycle: PASS; genuine local synthetic relay bytes observed')
        except Exception:
            if log.exists():
                print('Synthetic UDP helper diagnostics (last metadata lines):', file=sys.stderr)
                print(log.read_text(errors='replace')[-12000:], file=sys.stderr)
            raise
        finally:
            cleanup_errors = []
            local_proxy_stopping.set()
            for proxy in local_proxy_sockets:
                proxy.close()
            for proxy_worker in local_proxy_workers:
                proxy_worker.join(2)
                if proxy_worker.is_alive():
                    cleanup_errors.append('local UDP proxy worker did not stop')
            if mock_peer is not None:
                try: mock_peer.stop()
                except Exception as error: cleanup_errors.append(str(error))
            for owner in clients:
                try: owner.close()
                except Exception as error: cleanup_errors.append(str(error))
            for process in (helper, server):
                try: stop_process(process)
                except Exception as error: cleanup_errors.append(str(error))
            if table_installed:
                try: checked(str(ROOT / 'backend/nft-teardown.sh'), stdout=subprocess.DEVNULL)
                except Exception as error: cleanup_errors.append(str(error))
            if namespace_created:
                try: checked(ip, 'netns', 'delete', namespace)
                except Exception as error: cleanup_errors.append(str(error))
            if link_created:
                subprocess.run([ip, 'link', 'delete', host_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if token.exists(): cleanup_errors.append('helper token remains')
            if table_installed and table_exists(nft): cleanup_errors.append('owned nft table remains')
            if cleanup_errors:
                raise RuntimeError('UDP multi cleanup failed: ' + '; '.join(cleanup_errors))
    print(f'synthetic UDP multi: {passed} probes PASS; owned resources cleaned; live ExitLag/gameplay NOT TESTED')
    return 0


if __name__ == '__main__':
    raise SystemExit(run_main(main))
