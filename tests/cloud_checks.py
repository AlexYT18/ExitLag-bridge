#!/usr/bin/env python3
"""Level 1 checks with reproducible commands and explicit machine-readable status."""
import argparse
import ast
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SKIP = 77


class Checks:
    def __init__(self, output):
        self.output = output
        output.mkdir(parents=True, exist_ok=True)
        self.results = []

    def record(self, name, status, reason="", **extra):
        entry = {"name": name, "status": status, **extra}
        if reason:
            entry["reason"] = reason
        self.results.append(entry)
        print(f"{status:4} {name}" + (f": {reason}" if reason else ""), flush=True)
        return status

    def run(self, name, command, *, needs=(), env=None, reason="", timeout=180, unit_test=False):
        absent = [tool for tool in needs if not shutil.which(tool)]
        if reason or absent:
            return self.record(name, "SKIP", reason or "missing tools: " + ", ".join(absent), command=command)
        log = self.output / ("".join(c if c.isalnum() else "_" for c in name) + ".log")
        started = time.monotonic()
        with log.open("w") as stream:
            try:
                result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                        stderr=subprocess.STDOUT, timeout=timeout, check=False)
                code = result.returncode
            except subprocess.TimeoutExpired:
                code = 124
                stream.write(f"\nCheck timed out after {timeout} seconds.\n")
            except OSError as error:
                code = 126
                stream.write(str(error) + "\n")
        lines = log.read_text(errors="replace").splitlines()
        status = "PASS" if code == 0 else "SKIP" if code == SKIP else "FAIL"
        detail = lines[-1] if lines and status != "PASS" else ""
        # Preserve unittest's case/skip counts inside each aggregate command.
        counts = {}
        for line in lines:
            match = re.fullmatch(r"Ran (\d+) tests? in .+", line)
            if match:
                counts["test_methods"] = int(match[1])
            match = re.search(r"\bskipped=(\d+)", line)
            if match:
                counts["skipped_methods"] = int(match[1])
        if code == 0 and unit_test:
            total = counts.get("test_methods", 0)
            skipped = counts.get("skipped_methods", 0)
            if skipped and skipped >= total:
                status, detail = "SKIP", "all unittest cases skipped"
            elif total == 0:
                status, detail = "FAIL", "unit command completed without running any unittest cases"
        self.record(name, status, detail, command=command, exit_code=code,
                    seconds=round(time.monotonic() - started, 3), log=str(log), **counts)
        if status == "FAIL":
            print("\n".join(lines[-12:]), flush=True)
        return status

    def finish(self):
        counts = {status: Counter(x["status"] for x in self.results)[status]
                  for status in ("PASS", "FAIL", "SKIP")}
        report = {"schema_version": 1, "validation_level": 1,
                  "environment": {"platform": platform.platform(), "python": platform.python_version(),
                                  "uid": os.getuid() if hasattr(os, "getuid") else None},
                  "results": self.results, "summary": counts}
        path = self.output / "results.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"\n{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['SKIP']} SKIP; {path}")
        return 1 if counts["FAIL"] else 0


def syntax(checks):
    sources = sorted(path for path in ROOT.rglob("*.py")
                     if not any(part in (".git", "build", "runtime", "payloads", "vendor") for part in path.parts))
    try:
        for path in sources:
            ast.parse(path.read_text(), filename=str(path))
    except (SyntaxError, UnicodeError, OSError) as error:
        checks.record("Python syntax", "FAIL", str(error))
    else:
        checks.record("Python syntax", "PASS", f"{len(sources)} source files")
    shells = sorted(str(p.relative_to(ROOT)) for p in ROOT.rglob("*.sh")
                    if not any(part in (".git", "build", "runtime", "payloads", "vendor") for part in p.parts))
    checks.run("Shell syntax", ["bash", "-c", 'for script in "$@"; do bash -n "$script" || exit; done',
                                "syntax", *shells], needs=("bash",))
    checks.run("ShellCheck source errors", ["shellcheck", "-S", "error", *shells], needs=("shellcheck",))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--sanitizers", action="store_true", help="also run ASan/UBSan native checks")
    args = parser.parse_args()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}"
    checks = Checks((args.output_dir or ROOT / "runtime/logs" / ("cloud-" + stamp)).resolve())
    syntax(checks)
    python_suites = ["test_discovery_filters.py", "test_identity_tools.py", "test_installer.py",
                     "test_linux_desktop.py", "test_linux_launcher.py", "test_mac_distribution.py",
                     "test_process_picker.py", "test_game_picker.py", "test_linux_packaging.py",
                     "test_source_audit.py", "test_runner.py", "test-integration-support.py",
                     "test_benchmark_ipc.py", "test_llvm_toolchain.py"]
    for filename in python_suites:
        checks.run(filename, [sys.executable, "tests/" + filename], unit_test=True)
    checks.run("Tk process picker integration", [sys.executable, "tests/gui-picker-smoke.py"],
               needs=("Xvfb",), unit_test=True)
    checks.run("macOS account-free units", [sys.executable, "-m", "unittest", "discover", "-s", "macos", "-p", "test_*.py", "-v"], unit_test=True)
    cc = shlex.split(os.environ.get("CC", "cc"))
    cxx = shlex.split(os.environ.get("CXX", "c++"))
    compiler = cc[0] if cc else "cc"
    checks.run("Native IPC transport", ["make", "-B", "-C", "backend", "check-ipc"], needs=("make", compiler))
    checks.run("Native NFQUEUE verdict encoding", ["make", "-B", "-C", "backend", "check-nfq-verdict"], needs=("make", compiler))
    checks.run("Shim IPC validation", ["bash", "tests/test-shim-validation.sh"], needs=("bash", cxx[0] if cxx else "c++"))
    helper = checks.run("Fresh backend build", ["make", "-B", "-C", "backend"], needs=("make", compiler))
    try:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
        loopback_reason = ""
    except OSError as error:
        loopback_reason = "loopback socket bind unavailable: " + str(error)
    helper_reason = "fresh backend build did not pass" if helper != "PASS" else loopback_reason
    checks.run("Native TCP attribution", ["make", "-B", "-C", "backend", "check-tcp-attribution"], needs=("make", compiler), reason=loopback_reason)
    checks.run("Native process identity", ["make", "-B", "-C", "backend", "check-process-identity"], needs=("make", compiler), reason=loopback_reason)
    for target, name in (("check-udp-attribution", "attribution"),
                         ("check-udp-packet", "packet codec"), ("check-udp-peers", "peer lifecycle"),
                         ("check-udp-lifecycle", "maintenance scheduler"),
                         ("check-udp-maintenance", "daemon maintenance")):
        checks.run("Native UDP " + name, ["make", "-B", "-C", "backend", target],
                   needs=("make", compiler), reason=loopback_reason if target in ("check-udp-attribution", "check-udp-maintenance") else "")
    checks.run("Shim socket attribution", ["bash", "tests/test-shim-attribution.sh"], needs=("bash", cxx[0] if cxx else "c++"))
    checks.run("Shim worker lifecycle", ["bash", "tests/test-shim-lifecycle.sh"], needs=("bash", cxx[0] if cxx else "c++"))
    checks.run("Shim PID domains", ["bash", "tests/test-shim-pid-domain.sh"], needs=("bash", cxx[0] if cxx else "c++"))
    checks.run("Authenticated backend IPC", [sys.executable, "tests/test_backend_ipc.py", "-v"], reason=helper_reason, unit_test=True)
    for filename in ("test-identity-map.sh", "rpc-surface-test.sh", "identity-assistant-test.sh"):
        checks.run(filename, ["bash", "tests/" + filename], needs=("bash",), reason=helper_reason)
    checks.run("Process discovery", ["bash", "tests/discovery-test.sh"], needs=("bash",), reason=loopback_reason)
    checks.run("Doctor diagnoses", ["bash", "tests/doctor-test.sh"], needs=("bash",))
    cl_driver = "clang-cl" if shutil.which("clang-cl") else "clang"
    pe_tools = (cl_driver, "lld-link", "llvm-dlltool")
    checks.run("Windows shim build", ["bash", "shim/nfapi/build.sh"], needs=pe_tools)
    checks.run("Windows driver presence image build", ["bash", "shim/nfextlag/build.sh"], needs=(cl_driver, "lld-link", "llvm-rc"))
    checks.run("Crash guard executable build only", ["bash", "tests/build-nfapi-compat-smoketest.sh"], needs=pe_tools)
    checks.run("ShellCheck runner scripts", ["shellcheck", "tests/run-cloud.sh", "tests/run-all.sh", "tests/run-isolated.sh"], needs=("shellcheck",))
    checks.run("Cppcheck native backend", ["cppcheck", "--check-level=exhaustive",
               "--enable=warning,performance,portability", "--error-exitcode=1", "--std=c11",
               "--suppress=missingIncludeSystem", "backend/exitlag-netd.c", "backend/ipc_transport.c",
               "backend/tcp_attribution.c", "backend/process_identity.c", "backend/nfq_verdict.c",
               "backend/udp_attribution.c", "backend/udp_packet.c", "backend/udp_peers.c"], needs=("cppcheck",))
    if shutil.which(compiler) and Path(compiler).name in ("gcc", "cc"):
        checks.run("GCC static analyzer IPC", [*cc, "-Wall", "-Wextra", "-Werror", "-fanalyzer", "-c", "backend/ipc_transport.c", "-o", str(checks.output / "ipc-analyzer.o")])
        for module in ("tcp_attribution", "process_identity", "nfq_verdict", "udp_attribution", "udp_packet", "udp_peers"):
            checks.run("GCC static analyzer " + module, [*cc, "-Wall", "-Wextra", "-Werror", "-fanalyzer", "-c", "backend/" + module + ".c", "-o", str(checks.output / (module + "-analyzer.o"))])
    else:
        checks.record("GCC static analyzer IPC", "SKIP", "requires GCC -fanalyzer")
    if args.sanitizers:
        flags = "-O1 -g -Wall -Wextra -fno-omit-frame-pointer -fsanitize=address,undefined"
        links = "-fsanitize=address,undefined"
        sanitizer_env = dict(os.environ)
        sanitizer_env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        checks.run("ASan UBSan native IPC transport", ["make", "-B", "-C", "backend", "check-ipc", "CFLAGS=" + flags, "LDFLAGS=" + links], needs=("make", compiler), env=sanitizer_env)
        checks.run("ASan UBSan NFQUEUE verdict encoding", ["make", "-B", "-C", "backend", "check-nfq-verdict", "CFLAGS=" + flags, "LDFLAGS=" + links], needs=("make", compiler), env=sanitizer_env)
        checks.run("ASan UBSan shim IPC validation", ["bash", "tests/test-shim-validation.sh", "--sanitize"], needs=("bash", cxx[0] if cxx else "c++"), env=sanitizer_env)
        for target, name in (("check-tcp-attribution", "TCP attribution"), ("check-process-identity", "process identity")):
            checks.run("ASan UBSan native " + name, ["make", "-B", "-C", "backend", target, "CFLAGS=" + flags, "LDFLAGS=" + links], needs=("make", compiler), env=sanitizer_env, reason=loopback_reason)
        for target, name in (("check-udp-attribution", "UDP attribution"), ("check-udp-packet", "UDP packet codec"),
                             ("check-udp-peers", "UDP peer lifecycle"),
                             ("check-udp-lifecycle", "UDP maintenance scheduler"),
                             ("check-udp-maintenance", "UDP daemon maintenance")):
            checks.run("ASan UBSan native " + name, ["make", "-B", "-C", "backend", target,
                       "CFLAGS=" + flags, "LDFLAGS=" + links], needs=("make", compiler), env=sanitizer_env,
                       reason=loopback_reason if target in ("check-udp-attribution", "check-udp-maintenance") else "")
        checks.run("ASan UBSan shim socket attribution", ["bash", "tests/test-shim-attribution.sh", "--sanitize"], needs=("bash", cxx[0] if cxx else "c++"), env=sanitizer_env)
        checks.run("ASan UBSan shim worker lifecycle", ["bash", "tests/test-shim-lifecycle.sh", "--sanitize"], needs=("bash", cxx[0] if cxx else "c++"), env=sanitizer_env)
        checks.run("ASan UBSan shim PID domains", ["bash", "tests/test-shim-pid-domain.sh", "--sanitize"], needs=("bash", cxx[0] if cxx else "c++"), env=sanitizer_env)
        sanitized = checks.run("ASan UBSan fresh backend", ["make", "-B", "-C", "backend", "CFLAGS=" + flags, "LDFLAGS=" + links], needs=("make", compiler), env=sanitizer_env)
        checks.run("ASan UBSan authenticated backend IPC", [sys.executable, "tests/test_backend_ipc.py", "-v"], env=sanitizer_env,
                   reason="sanitized build did not pass" if sanitized != "PASS" else loopback_reason, unit_test=True)
        # Keep the delivered helper in its ordinary build configuration.
        checks.run("Restore release backend build", ["make", "-B", "-C", "backend"], needs=("make", compiler))
        if "detect_leaks=0" in sanitizer_env.get("ASAN_OPTIONS", ""):
            checks.record("LeakSanitizer", "SKIP", "ASAN_OPTIONS explicitly disables leak checking in this environment")
    checks.record("Level 2 kernel routing", "SKIP", "separate disposable namespace test: tests/run-isolated.sh")
    checks.record("Level 3 live ExitLag and games", "SKIP", "requires legitimate client/subscription and a suitable game host")
    return checks.finish()


if __name__ == "__main__":
    raise SystemExit(main())
