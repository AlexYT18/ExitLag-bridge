#!/usr/bin/env python3
"""Account-free tests of the synthetic integration peer and safety gate.

Uses socketpairs and temporary token fixtures; no firewall, namespace, external
network, official client or root access is needed.
"""

import importlib.util
import os
import queue
import socket
import struct
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import integration_support as support


class FramingTests(unittest.TestCase):
    def setUp(self):
        self.left, self.right = socket.socketpair()
        self.left.settimeout(1)
        self.right.settimeout(1)
        self.addCleanup(self.left.close)
        self.addCleanup(self.right.close)

    def test_binary_frame_round_trip(self):
        support.send_frame(self.left, 0x0046, b'\x00payload\xff')
        self.assertEqual(support.receive_frame(self.right), (0x0046, b'\x00payload\xff'))

    def test_rejects_invalid_header_without_reading_declared_body(self):
        for magic, flags, length in ((0, 0, 0), (support.MAGIC, 1, 0),
                                     (support.MAGIC, 0, support.MAX_PAYLOAD + 1)):
            with self.subTest(magic=magic, flags=flags, length=length):
                self.left.sendall(support.HEADER.pack(magic, 0x0010, flags, length))
                with self.assertRaisesRegex(RuntimeError, 'invalid IPC frame'):
                    support.receive_frame(self.right)

    def test_truncated_payload_reports_eof(self):
        self.left.sendall(support.HEADER.pack(support.MAGIC, 0x0010, 0, 4) + b'ab')
        self.left.shutdown(socket.SHUT_WR)
        with self.assertRaisesRegex(RuntimeError, 'unexpected IPC EOF'):
            support.receive_frame(self.right)

    def test_heartbeat_requires_empty_ping_and_replies_pong(self):
        self.assertTrue(support.respond_to_heartbeat(self.left, support.PING, b''))
        self.assertEqual(support.receive_frame(self.right), (support.PONG, b''))
        self.assertFalse(support.respond_to_heartbeat(self.left, 0x0010, b''))
        with self.assertRaisesRegex(RuntimeError, 'PING unexpectedly'):
            support.respond_to_heartbeat(self.left, support.PING, b'x')


class AuthenticationTests(unittest.TestCase):
    def handshake(self, acknowledgement):
        peer, server = socket.socketpair()
        peer.settimeout(1)
        server.settimeout(1)
        observed, errors = [], queue.Queue()

        def responder():
            try:
                observed.append(support.receive_frame(server))
                support.send_frame(server, support.HELLO_ACK, acknowledgement)
            except Exception as error:
                errors.put(error)

        worker = threading.Thread(target=responder, daemon=True)
        with tempfile.TemporaryDirectory(prefix='exitlag-peer-unit-') as work:
            token = Path(work) / 'token'
            token.write_text(bytes(range(32)).hex() + '\n')
            process = SimpleNamespace(pid=1234, poll=lambda: None)
            worker.start()
            try:
                with mock.patch.object(support.socket, 'create_connection', return_value=peer):
                    support.authenticate(1, token, process)
            finally:
                support.close_socket(peer)
                worker.join(2)
                server.close()
                self.assertFalse(worker.is_alive(), 'fake helper worker leaked')
                if not errors.empty():
                    raise errors.get_nowait()
        return observed

    def test_v3_hello_contains_exact_session_token(self):
        observed = self.handshake(struct.pack('<IIQ', 3, 1234, 0))
        self.assertEqual(len(observed), 1)
        kind, body = observed[0]
        self.assertEqual(kind, support.HELLO)
        self.assertEqual(struct.unpack('<IIQ32s', body), (3, 4242, 0, bytes(range(32))))

    def test_rejects_old_version_or_another_helper_pid(self):
        for version, pid in ((2, 1234), (3, 9999)):
            with self.subTest(version=version, pid=pid):
                with self.assertRaisesRegex(RuntimeError, 'does not match this v3 session'):
                    self.handshake(struct.pack('<IIQ', version, pid, 0))

    def test_rejects_short_acknowledgement(self):
        with self.assertRaisesRegex(RuntimeError, 'HELLO_ACK framing'):
            self.handshake(b'bad')


class HarnessSafetyTests(unittest.TestCase):
    def load_harness(self, filename):
        path = Path(__file__).with_name(filename)
        spec = importlib.util.spec_from_file_location(filename.replace('-', '_'), path)
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(support.subprocess, 'Popen') as popen:
            spec.loader.exec_module(module)
            popen.assert_not_called()
        return module

    def test_import_has_no_execution_and_missing_isolation_prevents_startup(self):
        for filename in ('test-tcp-redirect.py', 'test-udp-observe.py'):
            with self.subTest(harness=filename):
                module = self.load_harness(filename)
                with mock.patch.object(module, 'require_isolation',
                                       side_effect=support.PrerequisiteUnavailable('fixture gate')):
                    with mock.patch.object(support.subprocess, 'Popen') as popen:
                        with mock.patch.object(support.subprocess, 'run') as run:
                            with self.assertRaises(support.PrerequisiteUnavailable):
                                module.main()
                            popen.assert_not_called()
                            run.assert_not_called()

    def test_marker_alone_does_not_accept_host_namespaces(self):
        environment = {'EXITLAG_TEST_ISOLATED': '1', 'EXITLAG_TEST_HOST_NETNS': 'net:[1]',
                       'EXITLAG_TEST_HOST_PIDNS': 'pid:[2]'}
        with mock.patch.dict(os.environ, environment, clear=True):
            with mock.patch.object(support.os, 'geteuid', return_value=0):
                with mock.patch.object(support.os, 'readlink', return_value='net:[1]'):
                    with self.assertRaisesRegex(support.PrerequisiteUnavailable, 'not established'):
                        support.require_isolation()


if __name__ == '__main__':
    unittest.main()
