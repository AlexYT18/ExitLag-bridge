"""Account-free tests of the actual helper's IPC server.

All helpers run with --no-queue. The self-test event uses a deliberately
synthetic callback provider; these tests establish no ExitLag/game support.
"""
from __future__ import annotations

import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = Path(os.environ.get("EXITLAG_NETD_BIN", ROOT / "backend" / "exitlag-netd"))
MAGIC = 0x314C5845
HEADER = struct.Struct("<IHHI")


def frame(kind, payload=b"", flags=0):
    return HEADER.pack(MAGIC, kind, flags, len(payload)) + payload


def exact(sock, length):
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise EOFError("IPC peer disconnected")
        data.extend(chunk)
    return bytes(data)


def receive(sock, expected):
    while True:
        magic, kind, flags, length = HEADER.unpack(exact(sock, HEADER.size))
        if magic != MAGIC or flags or length > 131072:
            raise AssertionError("malformed helper frame")
        payload = exact(sock, length)
        if kind == 3 and not payload:
            sock.sendall(frame(4))
            continue
        if kind != expected:
            raise AssertionError(f"expected {expected:#x}, received {kind:#x}")
        return payload


@unittest.skipUnless(HELPER.is_file(), "exitlag-netd is not built; run make -C backend")
class BackendIPCTests(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="exl-ipc-test-")
        self.directory = Path(self.work.name)
        self.token_path = self.directory / "token"
        self.log_path = self.directory / "helper.log"
        self.process = None
        self.sockets = []
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]

    def tearDown(self):
        for sock in self.sockets:
            sock.close()
        if self.process is not None:
            self.process.terminate()
            try:
                self.process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.communicate(timeout=5)
                self.fail("helper failed to terminate within bounded cleanup timeout")
        self.work.cleanup()

    def start(self, *extra):
        environment = dict(os.environ)
        environment.pop("EXITLAG_IDENTITY_MAP", None)
        environment.update(getattr(self, "environment", {}))
        self.process = subprocess.Popen(
            [str(HELPER), "--no-queue", "--port", str(self.port),
             "--timeout-ms", "120", "--token-file", str(self.token_path),
             "--log", str(self.log_path), *extra],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=environment,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                _, stderr = self.process.communicate()
                self.fail(f"helper exited during startup: {stderr!r}")
            if (self.token_path.is_file() and self.log_path.is_file()
                    and "listening for shim" in self.log_path.read_text()):
                self.token = bytes.fromhex(self.token_path.read_text().strip())
                return
            time.sleep(0.01)
        self.fail("helper readiness was not observed")

    def connect(self):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        sock.settimeout(3)
        self.sockets.append(sock)
        return sock

    def hello(self, sock, *, token=None, version=3, flags=0, trailing=b""):
        body = struct.pack("<IIQ", version, 4242, 0)
        body += self.token if token is None else token
        sock.sendall(frame(1, body + trailing, flags))

    def authenticate(self):
        sock = self.connect()
        self.hello(sock)
        ack = receive(sock, 2)
        self.assertEqual(len(ack), 16)
        self.assertEqual(struct.unpack_from("<I", ack)[0], 3)
        return sock

    def assert_closed(self, sock):
        try:
            self.assertEqual(sock.recv(1), b"")
        except (ConnectionResetError, BrokenPipeError):
            pass

    def resolve_probe(self, sock, tag=99):
        sock.sendall(frame(0x20, struct.pack("<QII", tag, 0, 0)))
        body = receive(sock, 0x21)
        self.assertEqual(body, struct.pack("<QII", tag, 0, 0))

    def test_valid_session_and_secret_hygiene(self):
        self.start()
        sock = self.authenticate()
        self.resolve_probe(sock)
        self.assertNotIn(self.token.hex(), self.log_path.read_text())
        self.assertEqual(self.token_path.stat().st_mode & 0o777, 0o600)

    def test_udp_post_diagnostics_do_not_capture_payload(self):
        self.start()
        sock = self.authenticate()
        canary = b"PRIVATE_DATAGRAM_CANARY_12345678"
        remote = struct.pack("<H", 2) + struct.pack(">H", 1234) + socket.inet_aton("198.51.100.2") + bytes(20)
        # Synthetic nested post, deliberately outside any actual packet event.
        post = struct.pack("<QQIi28sIII", 1, 1, 1, 0, remote, 0, 0, len(canary)) + canary
        sock.sendall(frame(0x46, post))
        self.resolve_probe(sock)
        log = self.log_path.read_text()
        self.assertIn("nf_udpPostSend", log)
        self.assertIn("metadata-only", log)
        self.assertNotIn(canary.decode(), log)
        self.assertNotIn(canary.hex(), log)
        self.assertNotIn("head=", log)
        self.assertNotIn("hash=", log)

    def test_existing_log_is_private_before_any_diagnostics(self):
        self.log_path.write_text("existing harmless diagnostics\n")
        self.log_path.chmod(0o666)
        self.start()
        self.assertEqual(self.log_path.stat().st_mode & 0o777, 0o600)
        self.resolve_probe(self.authenticate())
        self.assertTrue(self.log_path.read_text().startswith("existing harmless diagnostics\n"))

    def test_log_rotation_keeps_private_regular_files(self):
        self.environment = {"EXITLAG_LOG_MAX_BYTES": "1"}
        self.start()
        sock = self.authenticate()
        for tag in range(300):
            self.resolve_probe(sock, tag)
        rotated = self.log_path.with_name(self.log_path.name + ".1")
        self.assertTrue(rotated.is_file(), "rotation was not exercised")
        for path in (self.log_path, rotated):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.stat().st_nlink, 1)

    def test_log_rejects_symlink_fifo_hardlink_and_symlink_parent(self):
        protected = self.directory / "protected"
        protected.write_text("must remain unchanged")
        symlink = self.directory / "symlink.log"
        symlink.symlink_to(protected)
        fifo = self.directory / "fifo.log"
        os.mkfifo(fifo)
        hardlink = self.directory / "hardlink.log"
        os.link(protected, hardlink)
        linked_parent = self.directory / "linked-parent"
        linked_parent.symlink_to(self.directory, target_is_directory=True)
        environment = dict(os.environ)
        environment.pop("EXITLAG_IDENTITY_MAP", None)
        for path in (symlink, fifo, hardlink, linked_parent / "other.log"):
            with self.subTest(path=path.name):
                before = time.monotonic()
                result = subprocess.run(
                    [str(HELPER), "--no-queue", "--log", str(path)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, env=environment,
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"log", result.stderr)
                self.assertLess(time.monotonic() - before, 2)
                self.assertEqual(protected.read_text(), "must remain unchanged")

    def test_rejected_candidates_do_not_evict_active_session(self):
        self.start()
        active = self.authenticate()
        candidates = [
            dict(token=b"\0" * 32), dict(version=2), dict(flags=1),
            dict(trailing=b"surplus"),
        ]
        for index, options in enumerate(candidates):
            with self.subTest(options=list(options)):
                candidate = self.connect()
                self.hello(candidate, **options)
                self.assert_closed(candidate)
                self.resolve_probe(active, index + 1)

    def test_authenticated_replacement_serves_new_session(self):
        self.start()
        previous = self.authenticate()
        replacement = self.authenticate()
        # The old connection may still have a queued heartbeat; drain it.
        previous.settimeout(1)
        while True:
            try:
                if not previous.recv(4096):
                    break
            except ConnectionResetError:
                break
        self.resolve_probe(replacement)

    def test_reserved_flags_and_oversized_frames_disconnect(self):
        self.start()
        for data in (frame(4, flags=1), HEADER.pack(MAGIC, 4, 0, 131073),
                     HEADER.pack(0, 4, 0, 0)):
            with self.subTest(data=data.hex()):
                sock = self.authenticate()
                # Consume any heartbeat by requesting an ordered response.
                self.resolve_probe(sock)
                sock.sendall(data)
                self.assert_closed(sock)
        self.resolve_probe(self.authenticate())

    def test_second_hello_disconnects_authenticated_session(self):
        self.start()
        sock = self.authenticate()
        self.resolve_probe(sock)
        self.hello(sock)
        self.assert_closed(sock)
        self.resolve_probe(self.authenticate())

    def test_resolve_request_requires_exact_size_and_zero_reserved(self):
        self.start()
        for payload in (struct.pack("<QII", 1, 0, 1),
                        struct.pack("<QII", 1, 0, 0) + b"x",
                        b"short"):
            with self.subTest(payload=payload.hex()):
                sock = self.authenticate()
                self.resolve_probe(sock)
                sock.sendall(frame(0x20, payload))
                self.assert_closed(sock)
        self.resolve_probe(self.authenticate())

    def test_partial_frame_disconnect_and_recovery(self):
        self.start()
        sock = self.authenticate()
        self.resolve_probe(sock)
        sock.sendall(HEADER.pack(MAGIC, 0x20, 0, 16) + b"\0")
        before = time.monotonic()
        self.assert_closed(sock)
        self.assertLess(time.monotonic() - before, 1.0)
        self.resolve_probe(self.authenticate())

    def test_header_dribble_has_total_handshake_deadline(self):
        self.start()
        candidate = self.connect()
        before = time.monotonic()
        closed = False
        # Each byte arrives well within the old per-read 2 s timeout.
        for byte in frame(1, struct.pack("<IIQ", 3, 4242, 0) + self.token):
            try:
                candidate.sendall(bytes([byte]))
            except (BrokenPipeError, ConnectionResetError):
                closed = True
                break
            time.sleep(0.15)
            if time.monotonic() - before > 3:
                break
        if not closed:
            candidate.settimeout(0.3)
            self.assert_closed(candidate)
        self.assertLess(time.monotonic() - before, 3.5)
        self.resolve_probe(self.authenticate())

    def synthetic_rpc_flood(self, kind):
        self.start("--self-test", "198.51.100.1:80")
        sock = self.authenticate()
        request = receive(sock, 0x10)
        tag = struct.unpack_from("<Q", request)[0]
        if kind == "stale":
            body = struct.pack("<QII28sBBBB", tag + 1, 0, 0, bytes(28), 0, 0, 0, 0)
            noise = frame(0x11, body)
        elif kind == "nested":
            noise = frame(4)
        else:
            body = struct.pack("<QII28sBBBB", tag, 0, 0, bytes(28), 0, 0, 0, 0)
            noise = frame(0x11, body + b"surplus")
        before = time.monotonic()
        closed = False
        sock.settimeout(0.01)
        while time.monotonic() - before < 0.8:
            try:
                sock.sendall(noise)
                if not sock.recv(1):
                    closed = True
                    break
            except socket.timeout:
                continue
            except (BrokenPipeError, ConnectionResetError):
                closed = True
                break
        self.assertTrue(closed, "synthetic nested/stale replies extended the RPC deadline")
        self.assertLess(time.monotonic() - before, 0.8)
        deadline = time.monotonic() + 1
        while ("self-test: no reply from shim" not in self.log_path.read_text()
               and time.monotonic() < deadline):
            time.sleep(0.01)
        self.assertIn("self-test: no reply from shim", self.log_path.read_text())

    def test_synthetic_stale_replies_cannot_extend_rpc_deadline(self):
        self.synthetic_rpc_flood("stale")

    def test_synthetic_nested_replies_cannot_extend_rpc_deadline(self):
        self.synthetic_rpc_flood("nested")

    def test_synthetic_surplus_reply_is_not_accepted(self):
        self.synthetic_rpc_flood("surplus")

    def test_timeout_argument_is_strictly_positive_and_bounded(self):
        for value in ("0", "-1", "60001", "junk", "120junk", "999999999999999999999"):
            with self.subTest(value=value):
                result = subprocess.run([str(HELPER), "--no-queue", "--timeout-ms", value],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"--timeout-ms", result.stderr)


if __name__ == "__main__":
    unittest.main()
