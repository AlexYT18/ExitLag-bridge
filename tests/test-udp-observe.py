#!/usr/bin/env python3
"""One synthetic IPv4 UDP endpoint through real NFQUEUE and a local veth peer.

Run through tests/run-isolated.sh, optionally with --steer for the existing
single-endpoint take/reinject contract. No official client/account is involved;
this test does not establish live game compatibility or general UDP steering.
"""

import json
import os
import queue
import re
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

from integration_support import (
    authenticate, available_port, checked, close_socket, receive_frame,
    require_isolation, required_tool, respond_to_heartbeat, run_main,
    send_frame, stop_process, table_exists, wait_for_log,
)


UDP_CREATED, UDP_CREATED_REPLY = 0x0040, 0x0041
UDP_CONNECT, UDP_CONNECT_REPLY = 0x0042, 0x0043
UDP_DATAGRAM, UDP_DATAGRAM_REPLY = 0x0044, 0x0045
UDP_POST, UDP_STATE = 0x0046, 0x0047
UDP_CLOSED, UDP_CLOSED_REPLY = 0x0048, 0x0049
POST_SEND, POST_RECEIVE, ADD_REMOTE_RULE, SET_FLOWCTL = 1, 2, 3, 6
HOST_IP, PEER_IP, PEER_PORT = '198.51.100.1', '198.51.100.2', 49000
ROOT = Path(__file__).resolve().parent.parent


def echo_server(arguments):
    address, port, ready_path, result_path = arguments
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.settimeout(15)
        server.bind((address, int(port)))
        Path(ready_path).write_text('ready\n')
        payload, peer = server.recvfrom(65535)
        server.sendto(b'reply:' + payload, peer)
        Path(result_path).write_text(json.dumps({'payload': payload.hex(), 'peer': peer}))
    return 0


def mock_shim(sock, observed, datagrams, errors, closed, stopping, heartbeat, active):
    try:
        while not stopping.is_set():
            kind, body = receive_frame(sock)
            if respond_to_heartbeat(sock, kind, body):
                heartbeat.set()
                continue
            if kind in (UDP_CREATED, UDP_CLOSED):
                tag, endpoint, pid, family, local = struct.unpack('<QQIH28s', body)
                observed.append('udpCreated' if kind == UDP_CREATED else 'udpClosed')
                reply = struct.pack('<QIIH28sB3s', tag, 0, pid, family, local, 0, bytes(3))
                send_frame(sock, UDP_CREATED_REPLY if kind == UDP_CREATED else UDP_CLOSED_REPLY, reply)
                if kind == UDP_CLOSED:
                    closed.set()
                    return
            elif kind == UDP_CONNECT:
                tag, endpoint, pid, flag, family, local, remote = struct.unpack('<QQIIH28s28s', body)
                if family != 2 or socket.inet_ntoa(remote[4:8]) != PEER_IP:
                    raise RuntimeError('unexpected UDP connect endpoint')
                observed.append('udpConnectRequest')
                send_frame(sock, UDP_CONNECT_REPLY,
                           struct.pack('<QIII28sBB2s', tag, 0, pid, flag, remote, 0, 0, bytes(2)))
            elif kind == UDP_DATAGRAM:
                fixed = struct.calcsize('<QQIBBH28s28sIII')
                values = struct.unpack('<QQIBBH28s28sIII', body[:fixed])
                tag, endpoint, pid, direction, reserved, family, local, remote, flags, options_len, data_len = values
                if family != 2 or direction not in (1, 2) or len(body) != fixed + options_len + data_len:
                    raise RuntimeError('unexpected UDP datagram framing/family/direction')
                options = body[fixed:fixed + options_len]
                data = body[fixed + options_len:]
                observed.append('udpSend' if direction == 2 else 'udpReceive')
                datagrams.append((direction, data))
                api = POST_SEND if direction == 2 else POST_RECEIVE
                post = struct.pack('<QQIi28sIII', tag, endpoint, api, 0, remote, flags, len(options), len(data))
                send_frame(sock, UDP_POST, post + options + data)
                rules = controls = 0
                if direction == 2:
                    if not active:
                        send_frame(sock, UDP_STATE, struct.pack('<QQIiII', tag, endpoint, SET_FLOWCTL, 0, 3, 0))
                        controls = 1
                    rule = remote[4:8][::-1] + bytes(12) + remote[2:4] + struct.pack('<H', 1)
                    send_frame(sock, UDP_STATE,
                               struct.pack('<QQIiII', tag, endpoint, ADD_REMOTE_RULE, 0, 0, len(rule)) + rule)
                    rules = 1
                send_frame(sock, UDP_DATAGRAM_REPLY,
                           struct.pack('<QIIIIBBBB', tag, 0, 1, rules, controls, 0, 0, 0, 0))
            else:
                raise RuntimeError(f'unexpected helper message {kind:#x}')
    except Exception as error:
        if not stopping.is_set():
            errors.put(error)


def main():
    require_isolation()  # Before creating namespaces, links, sockets or helper.
    if sys.argv[1:2] == ['--echo-server']:
        if len(sys.argv) != 6:
            raise RuntimeError('invalid internal echo-server arguments')
        return echo_server(sys.argv[2:])
    if sys.argv[1:] not in ([], ['--steer']):
        raise RuntimeError('usage: test-udp-observe.py [--steer] via tests/run-isolated.sh')
    active = sys.argv[1:] == ['--steer']
    nft, ip = required_tool('nft'), required_tool('ip')
    if table_exists(nft):
        raise RuntimeError('refusing to touch pre-existing table inet exitlag')
    suffix = secrets.token_hex(3)
    namespace, host_if, peer_if = 'exludp-' + suffix, 'exluh' + suffix, 'exlup' + suffix
    ipc_port = available_port()
    tcp_queue = 1000 + (os.getpid() % 1000) * 2
    udp_queue = tcp_queue + 1
    namespace_created = link_created = table_installed = False
    helper = server = shim = worker = None
    observed, datagrams, errors = [], [], queue.Queue()
    closed, stopping, heartbeat = threading.Event(), threading.Event(), threading.Event()

    with tempfile.TemporaryDirectory(prefix='exitlag-udp-test-') as work:
        work = Path(work)
        log, token = work / 'netd.log', work / 'token'
        ready, result = work / 'server.ready', work / 'server.json'
        try:
            checked(ip, 'netns', 'add', namespace)
            namespace_created = True
            checked(ip, 'link', 'add', host_if, 'type', 'veth', 'peer', 'name', peer_if)
            link_created = True
            checked(ip, 'link', 'set', peer_if, 'netns', namespace)
            checked(ip, 'addr', 'add', HOST_IP + '/24', 'dev', host_if)
            checked(ip, 'link', 'set', host_if, 'up')
            checked(ip, 'netns', 'exec', namespace, ip, 'link', 'set', 'lo', 'up')
            checked(ip, 'netns', 'exec', namespace, ip, 'addr', 'add', PEER_IP + '/24', 'dev', peer_if)
            checked(ip, 'netns', 'exec', namespace, ip, 'link', 'set', peer_if, 'up')
            server = subprocess.Popen([
                ip, 'netns', 'exec', namespace, sys.executable, str(Path(__file__).resolve()),
                '--echo-server', PEER_IP, str(PEER_PORT), str(ready), str(result),
            ])
            wait_for_log(ready, 'ready', server)
            helper_env = os.environ.copy()
            helper_env.pop('EXITLAG_IDENTITY_MAP', None)
            helper = subprocess.Popen([
                str(ROOT / 'backend/exitlag-netd'), '--queue', str(tcp_queue),
                '--udp-queue', str(udp_queue), '--port', str(ipc_port),
                '--apply-udp' if active else '--observe-udp',
                *(['--udp-active-once'] if active else []),
                '--peer-uid', str(os.geteuid()), '--token-file', str(token), '--log', str(log),
            ], env=helper_env)
            wait_for_log(log, f'bound UDP NFQUEUE {udp_queue}', helper)
            shim = authenticate(ipc_port, token, helper)
            shim.settimeout(8)
            worker = threading.Thread(target=mock_shim,
                                      args=(shim, observed, datagrams, errors, closed, stopping, heartbeat, active),
                                      daemon=True)
            worker.start()
            if not heartbeat.wait(5):
                if not errors.empty():
                    raise errors.get_nowait()
                raise RuntimeError('no helper heartbeat observed by synthetic peer')

            env = os.environ.copy()
            env.update(QUEUE_NUM=str(tcp_queue), TEST_DEST='203.0.113.1',
                       UDP_QUEUE_NUM=str(udp_queue), UDP_TEST_DEST=PEER_IP,
                       UDP_TEST_PORT=str(PEER_PORT), ENABLE_UDP_OBSERVE='1',
                       ENABLE_UDP_STEER='1' if active else '0')
            env.pop('EXL_USER_UID', None)
            checked(str(ROOT / 'backend/nft-setup.sh'), env=env, stdout=subprocess.DEVNULL)
            table_installed = True
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.settimeout(5)
                client.sendto(b'ping', (PEER_IP, PEER_PORT))
                reply, peer = client.recvfrom(128)
                if reply != b'reply:ping' or peer != (PEER_IP, PEER_PORT):
                    raise RuntimeError(f'bad UDP reply {reply!r} from {peer}')
            if not closed.wait(6):
                if not errors.empty():
                    raise errors.get_nowait()
                raise RuntimeError('udpClosed missing after socket teardown')
            worker.join(1)
            if worker.is_alive():
                raise RuntimeError('UDP callback worker failed to finish')
            if not errors.empty():
                raise errors.get_nowait()
            server.wait(timeout=3)
            if server.returncode != 0:
                raise RuntimeError(f'UDP echo server failed: {server.returncode}')
            assert json.loads(result.read_text())['payload'] == b'ping'.hex()
            expected = ['udpCreated', 'udpConnectRequest', 'udpSend', 'udpReceive', 'udpClosed']
            assert observed == expected, observed
            assert datagrams == [(2, b'ping'), (1, b'reply:ping')], datagrams
            log_text = log.read_text(errors='replace')
            required = ['nf_udpPostSend', 'nf_udpPostReceive', 'nf_udpAddRemoteAddrRule',
                        'udp udpClosed', 'remote_rules_deleted=1']
            if active:
                required += ['DROP original; POST_SEND reinjected with bypass mark',
                             'ACCEPT POST_RECEIVE reply to original socket']
                rules = checked(nft, 'list', 'table', 'inet', 'exitlag', text=True, capture_output=True).stdout
                if not re.search(r'mark 0x584c0001 counter packets 1 bytes [0-9]+ accept', rules):
                    raise RuntimeError(f'expected one marked replacement packet, ruleset: {rules}')
            else:
                required += ['nf_setUDPFlowCtl', 'ACCEPT unchanged (UDP observe)']
                if 'DROP original' in log_text:
                    raise RuntimeError('observation mode unexpectedly dropped a datagram')
            missing = [entry for entry in required if entry not in log_text]
            if missing:
                raise RuntimeError(f'missing helper evidence: {missing}')
            print('callback sequence:', ' -> '.join(observed))
            print('heartbeat, bidirectional payload, nested post/rule and endpoint close: PASS')
        except Exception:
            if not errors.empty():
                raise errors.get_nowait()
            raise
        finally:
            stopping.set()
            close_socket(shim)
            cleanup_errors = []
            if worker is not None:
                worker.join(9)
                if worker.is_alive():
                    cleanup_errors.append('UDP callback worker did not stop')
            try:
                if table_installed:
                    checked(str(ROOT / 'backend/nft-teardown.sh'), stdout=subprocess.DEVNULL)
            except Exception as error:
                cleanup_errors.append(str(error))
            for process in (helper, server):
                try:
                    stop_process(process)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if namespace_created:
                try:
                    checked(ip, 'netns', 'delete', namespace)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if link_created and subprocess.run([ip, 'link', 'show', host_if],
                                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                try:
                    checked(ip, 'link', 'delete', host_if)
                except Exception as error:
                    cleanup_errors.append(str(error))
            if token.exists():
                cleanup_errors.append('helper session token remains')
            if table_installed and table_exists(nft):
                cleanup_errors.append('table inet exitlag remains')
            if cleanup_errors:
                raise RuntimeError('integration cleanup failed: ' + '; '.join(cleanup_errors))
    print(f'synthetic single-endpoint UDP {"steering" if active else "observation"}: PASS; owned resources cleaned up')
    return 0


if __name__ == '__main__':
    raise SystemExit(run_main(main))
