#!/usr/bin/env python3
"""Reproducible synthetic IPC baseline; never a game/relay/network benchmark.

Example: python3 tests/benchmark-ipc.py --binary backend/exitlag-netd \
    --iterations 5 --transactions 200 --output /tmp/ipc-benchmark.json
Run the identical command with the baseline binary for a fair comparison.
"""
import argparse
import hashlib
import json
import math
import os
import platform
from pathlib import Path
import socket
import statistics
import struct
import subprocess
import tempfile
import time

MAGIC = 0x314C5845


def exact(stream, size):
    parts = bytearray()
    while len(parts) < size:
        piece = stream.recv(size - len(parts))
        if not piece:
            raise RuntimeError("unexpected IPC EOF")
        parts.extend(piece)
    return bytes(parts)


def send(stream, kind, body=b""):
    stream.sendall(struct.pack("<IHHI", MAGIC, kind, 0, len(body)) + body)


def receive(stream, expected):
    while True:
        magic, kind, flags, size = struct.unpack("<IHHI", exact(stream, 12))
        if magic != MAGIC or flags or size > 131072:
            raise RuntimeError("invalid IPC frame")
        body = exact(stream, size)
        if kind == 3 and not body:
            send(stream, 4)
            continue
        if kind != expected:
            raise RuntimeError(f"unexpected IPC type: {kind}")
        return body


def resources(pid):
    # utime/stime are fields 14/15; split after the parenthesized comm field.
    tail = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    cpu = (int(tail[11]) + int(tail[12])) / os.sysconf("SC_CLK_TCK")
    status = Path(f"/proc/{pid}/status").read_text().splitlines()
    hwm = next(int(x.split()[1]) for x in status if x.startswith("VmHWM:"))
    return cpu, hwm


def one_run(binary, transactions):
    with tempfile.TemporaryDirectory(prefix="exl-ipc-bench-") as directory:
        temporary = Path(directory)
        token = temporary / "session.token"
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
        started = time.perf_counter()
        with (temporary / "stderr.txt").open("w") as errors:
            helper = subprocess.Popen([str(binary), "--no-queue", "--port", str(port),
                                       "--token-file", str(token), "--log", str(temporary / "helper.txt"),
                                       "--allow-any-pid-resolve"], stderr=errors,
                                      stdout=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while True:
                    if helper.poll() is not None:
                        raise RuntimeError("helper exited at startup: " + (temporary / "stderr.txt").read_text())
                    try:
                        secret = bytes.fromhex(token.read_text().strip())
                        if len(secret) != 32:
                            raise ValueError("token not ready")
                        stream = socket.create_connection(("127.0.0.1", port), timeout=2)
                        break
                    except (OSError, ValueError):
                        if time.monotonic() >= deadline:
                            raise RuntimeError("helper startup deadline expired")
                        time.sleep(.002)
                with stream:
                    send(stream, 1, struct.pack("<IIQ", 3, os.getpid(), 0) + secret)
                    ack = receive(stream, 2)
                    if len(ack) != 16 or struct.unpack_from("<I", ack)[0] != 3:
                        raise RuntimeError("bad protocol acknowledgement")
                    startup_ms = (time.perf_counter() - started) * 1000
                    elapsed = []
                    cpu_before, _ = resources(helper.pid)
                    workload_start = time.perf_counter()
                    for tag in range(1, transactions + 1):
                        before = time.perf_counter()
                        send(stream, 0x20, struct.pack("<QII", tag, os.getpid(), 0))
                        body = receive(stream, 0x21)
                        if len(body) < 16:
                            raise RuntimeError("short PID reply")
                        reply_tag, length, reserved = struct.unpack_from("<QII", body)
                        if reply_tag != tag or reserved or length != len(body) - 16 or not length:
                            raise RuntimeError("invalid PID reply")
                        elapsed.append((time.perf_counter() - before) * 1000)
                    workload_seconds = time.perf_counter() - workload_start
                    cpu_after, rss_kib = resources(helper.pid)
                stop_start = time.perf_counter()
                helper.terminate()
                helper.wait(timeout=3)
                stop_ms = (time.perf_counter() - stop_start) * 1000
                if helper.returncode != 0 or token.exists():
                    raise RuntimeError("helper shutdown/token cleanup failed")
                return {"startup_ms": startup_ms, "teardown_ms": stop_ms,
                        "transactions": transactions, "workload_seconds": workload_seconds,
                        "transactions_per_second": transactions / workload_seconds,
                        "helper_cpu_seconds": cpu_after - cpu_before,
                        "helper_peak_rss_kib": rss_kib, "latency_ms": elapsed}
            finally:
                if helper.poll() is None:
                    helper.kill()
                    helper.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--transactions", type=int, default=200)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.iterations < 1 or args.transactions < 1:
        parser.error("iterations and transactions must be positive")
    binary = args.binary.resolve(strict=True)
    runs = [one_run(binary, args.transactions) for _ in range(args.iterations)]
    latencies = sorted(value for run in runs for value in run["latency_ms"])
    def percentile(p):
        return latencies[max(0, math.ceil(len(latencies) * p) - 1)]
    summary = {"latency_p50_ms": percentile(.5), "latency_p95_ms": percentile(.95),
               "latency_p99_ms": percentile(.99), "latency_stdev_ms": statistics.pstdev(latencies),
               "median_transactions_per_second": statistics.median(r["transactions_per_second"] for r in runs),
               "median_startup_ms": statistics.median(r["startup_ms"] for r in runs),
               "median_teardown_ms": statistics.median(r["teardown_ms"] for r in runs),
               "max_helper_rss_kib": max(r["helper_peak_rss_kib"] for r in runs),
               "total_helper_cpu_seconds": sum(r["helper_cpu_seconds"] for r in runs)}
    report = {"schema_version": 1, "scope": "synthetic no-queue IPC only; not packet/relay/game performance",
              "environment": {"kernel": platform.release(), "machine": platform.machine(),
                              "python": platform.python_version(), "cpu_clock_tick_seconds": 1 / os.sysconf("SC_CLK_TCK")},
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "binary": str(binary), "iterations": args.iterations, "transactions_per_iteration": args.transactions,
              "packet_throughput_latency_jitter_loss_queue_saturation": "NOT TESTED",
              "summary": summary, "runs": runs}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
