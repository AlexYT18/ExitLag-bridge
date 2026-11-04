#!/usr/bin/env python3
"""Exercise suite exit semantics using child commands, without network access."""
from pathlib import Path
import contextlib
import importlib.util
import io
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cloud_checks", ROOT / "tests/cloud_checks.py")
cloud_checks = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cloud_checks)


class RunnerStatus(unittest.TestCase):
    def run_case(self, child, status, expected):
        with tempfile.TemporaryDirectory() as output:
            script = r'''
source "$1/tests/run-all.sh"
outdir="$2"
pass=0; fail=0; skip=0; results=()
run_test fixture none bash -c "$3"
printf 'COUNTS:%s:%s:%s\n' "$pass" "$fail" "$skip"
printf '%s\n' "${results[@]}"
'''
            result = subprocess.run(
                ["bash", "-c", script, "runner-fixture", str(ROOT), output, child],
                text=True, capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(status + "  fixture", result.stdout)
            self.assertIn("COUNTS:" + expected, result.stdout)
            return result.stdout

    def test_success_is_pass(self):
        self.run_case("exit 0", "PASS", "1:0:0")

    def test_failure_is_fail(self):
        self.run_case("echo deliberate-failure; exit 9", "FAIL", "0:1:0")

    def test_skip_code_preserves_reason_and_is_not_pass(self):
        output = self.run_case("echo 'SKIP: fixture dependency absent'; exit 77", "SKIP", "0:0:1")
        self.assertIn("fixture dependency absent", output)
        self.assertNotIn("PASS  fixture", output)

    def test_unknown_tier_is_error(self):
        result = subprocess.run(
            ["bash", str(ROOT / "tests/run-all.sh"), "unt"],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Unknown test tier", result.stderr)
        self.assertNotIn("passed", result.stdout)

    def test_sourcing_runner_does_not_execute_suite(self):
        result = subprocess.run(
            ["bash", "-c", 'source "$1/tests/run-all.sh"', "fixture", str(ROOT)],
            text=True, capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_marker_without_changed_namespaces_is_refused(self):
        script = r'''
source "$1/tests/run-all.sh"
EXITLAG_TEST_ISOLATED=1
EXITLAG_TEST_HOST_NETNS="$(readlink /proc/self/ns/net)"
EXITLAG_TEST_HOST_PIDNS="$(readlink /proc/self/ns/pid)"
have_isolation
'''
        result = subprocess.run(["bash", "-c", script, "fixture", str(ROOT)])
        self.assertNotEqual(result.returncode, 0)

    def test_legacy_network_tests_skip_before_mutating_host(self):
        for filename in ("harden-runtime-test.sh", "ipv6-redirect-test.sh"):
            with self.subTest(filename=filename):
                result = subprocess.run(["bash", str(ROOT / "tests" / filename)],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 77, result.stderr)
                self.assertIn("network and PID isolation required", result.stderr)


class CloudRunnerStatus(unittest.TestCase):
    def case(self, output, code=0, **kwargs):
        import sys
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            checks = cloud_checks.Checks(Path(directory))
            status = checks.run("fixture", [sys.executable, "-c", f"print({output!r}); raise SystemExit({code})"], **kwargs)
            return status, checks.results[-1]

    def test_zero_tests_are_failure(self):
        status, result = self.case("Ran 0 tests in 0.000s\nOK", unit_test=True)
        self.assertEqual(status, "FAIL")
        self.assertEqual(result["test_methods"], 0)

    def test_silent_unit_command_is_failure(self):
        status, _ = self.case("", unit_test=True)
        self.assertEqual(status, "FAIL")

    def test_all_skipped_cases_are_group_skip(self):
        status, result = self.case("Ran 2 tests in 0.001s\nOK (skipped=2)", unit_test=True)
        self.assertEqual(status, "SKIP")
        self.assertEqual(result["skipped_methods"], 2)

    def test_partial_skips_preserve_counts(self):
        status, result = self.case("Ran 5 tests in 0.001s\nOK (skipped=2)", unit_test=True)
        self.assertEqual(status, "PASS")
        self.assertEqual(result["test_methods"], 5)
        self.assertEqual(result["skipped_methods"], 2)

    def test_nonzero_exit_cannot_be_overridden_by_skip_text(self):
        status, _ = self.case("Ran 2 tests in 0.001s\nFAILED (errors=1, skipped=2)", code=1, unit_test=True)
        self.assertEqual(status, "FAIL")

    def test_exit_77_is_skip(self):
        status, _ = self.case("SKIP: unavailable fixture", code=77)
        self.assertEqual(status, "SKIP")

    def test_missing_tool_is_skip_and_command_does_not_run(self):
        status, result = self.case("must not execute", needs=("exl-deliberately-missing-test-tool",))
        self.assertEqual(status, "SKIP")
        self.assertIn("missing tools", result["reason"])
        self.assertNotIn("exit_code", result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
