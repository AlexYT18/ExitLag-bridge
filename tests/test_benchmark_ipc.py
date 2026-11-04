#!/usr/bin/env python3
"""Benchmark parser/report regressions using byte fixtures, never real sockets."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("benchmark_ipc", Path(__file__).with_name("benchmark-ipc.py"))
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


class ByteStream:
    def __init__(self, data, fragment=3):
        self.data = data
        self.fragment = fragment
        self.sent = []

    def recv(self, size):
        length = min(size, self.fragment)
        part, self.data = self.data[:length], self.data[length:]
        return part

    def sendall(self, data):
        self.sent.append(data)


def frame(kind, body=b"", *, magic=benchmark.MAGIC, flags=0, size=None):
    return struct.pack("<IHHI", magic, kind, flags, len(body) if size is None else size) + body


class Framing(unittest.TestCase):
    def test_exact_accumulates_fragmented_bytes(self):
        self.assertEqual(benchmark.exact(ByteStream(b"abcdef"), 6), b"abcdef")
        self.assertEqual(benchmark.exact(ByteStream(b""), 0), b"")

    def test_eof_mid_header_or_body_is_error(self):
        for data in (b"EXL", frame(2, b"body")[:-1]):
            with self.subTest(data=data), self.assertRaisesRegex(RuntimeError, "EOF"):
                benchmark.receive(ByteStream(data), 2)

    def test_invalid_magic_flags_or_oversized_length_are_rejected(self):
        for data in (frame(2, magic=0), frame(2, flags=1), frame(2, size=131073)):
            with self.subTest(data=data), self.assertRaisesRegex(RuntimeError, "invalid IPC frame"):
                benchmark.receive(ByteStream(data), 2)

    def test_expected_body_and_heartbeat_reply(self):
        stream = ByteStream(frame(3) + frame(2, b"acknowledgement"), fragment=1)
        self.assertEqual(benchmark.receive(stream, 2), b"acknowledgement")
        self.assertEqual(stream.sent, [frame(4)])

    def test_unexpected_type_is_error(self):
        with self.assertRaisesRegex(RuntimeError, "unexpected IPC type"):
            benchmark.receive(ByteStream(frame(99)), 2)

    def test_send_encodes_length_and_zero_flags(self):
        stream = ByteStream(b"")
        benchmark.send(stream, 0x20, b"fixture")
        self.assertEqual(stream.sent, [frame(0x20, b"fixture")])


class ResourceParsing(unittest.TestCase):
    def test_proc_stat_handles_spaces_and_parentheses_in_comm(self):
        fields = ["0"] * 40
        fields[0] = "S"
        fields[11], fields[12] = "200", "300"
        stat = "123 (name with ) and spaces)) " + " ".join(fields)
        status = "Name:\tfixture\nVmRSS:\t7 kB\nVmHWM:\t456 kB\n"
        with mock.patch.object(benchmark.Path, "read_text", side_effect=[stat, status]), \
                mock.patch.object(benchmark.os, "sysconf", return_value=100):
            self.assertEqual(benchmark.resources(123), (5.0, 456))

    def test_missing_or_malformed_proc_metrics_are_not_invented(self):
        for stat in ("malformed", "123 (fixture) S 0"):
            with self.subTest(stat=stat), mock.patch.object(benchmark.Path, "read_text", return_value=stat), \
                    self.assertRaises((IndexError, ValueError)):
                benchmark.resources(123)
        fields = ["0"] * 40
        stat = "123 (fixture) " + " ".join(fields)
        with mock.patch.object(benchmark.Path, "read_text", side_effect=[stat, "Name:\tfixture\n"]), \
                self.assertRaises(StopIteration):
            benchmark.resources(123)


class CommandLine(unittest.TestCase):
    def test_nonpositive_counts_fail_before_starting_helper(self):
        for flag, value in (("--iterations", "0"), ("--iterations", "-1"),
                            ("--transactions", "0"), ("--transactions", "-10")):
            args = ["benchmark", "--binary", "unused", "--output", "unused.json", flag, value]
            with self.subTest(flag=flag, value=value), mock.patch.object(sys, "argv", args), \
                    mock.patch.object(benchmark, "one_run") as run, \
                    contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                benchmark.main()
            self.assertEqual(error.exception.code, 2)
            run.assert_not_called()

    def test_missing_arguments_are_rejected(self):
        with mock.patch.object(sys, "argv", ["benchmark"]), \
                contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            benchmark.main()
        self.assertEqual(error.exception.code, 2)

    def test_synthetic_runs_produce_correct_percentiles_and_honest_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "fake-helper"
            binary.write_bytes(b"synthetic binary fixture; never executed")
            output = Path(directory) / "report.json"
            runs = [{"startup_ms": 1, "teardown_ms": 3, "transactions": 3,
                     "workload_seconds": .3, "transactions_per_second": 10,
                     "helper_cpu_seconds": .1, "helper_peak_rss_kib": 128,
                     "latency_ms": [1, 2, 3]},
                    {"startup_ms": 3, "teardown_ms": 5, "transactions": 3,
                     "workload_seconds": .15, "transactions_per_second": 20,
                     "helper_cpu_seconds": .2, "helper_peak_rss_kib": 256,
                     "latency_ms": [4, 5, 6]}]
            args = ["benchmark", "--binary", str(binary), "--output", str(output),
                    "--iterations", "2", "--transactions", "3"]
            with mock.patch.object(sys, "argv", args), \
                    mock.patch.object(benchmark, "one_run", side_effect=runs) as run, \
                    contextlib.redirect_stdout(io.StringIO()):
                benchmark.main()
            self.assertEqual(run.call_count, 2)
            report = json.loads(output.read_text())
            self.assertEqual(report["summary"]["latency_p50_ms"], 3)
            self.assertEqual(report["summary"]["latency_p95_ms"], 6)
            self.assertEqual(report["summary"]["latency_p99_ms"], 6)
            self.assertEqual(report["summary"]["median_transactions_per_second"], 15)
            self.assertEqual(report["summary"]["max_helper_rss_kib"], 256)
            self.assertIn("not packet/relay/game performance", report["scope"])
            self.assertEqual(report["packet_throughput_latency_jitter_loss_queue_saturation"], "NOT TESTED")


if __name__ == "__main__":
    unittest.main(verbosity=2)
