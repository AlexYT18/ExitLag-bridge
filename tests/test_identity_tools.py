#!/usr/bin/env python3
"""Account-free map policy tests; discovery is synthetic, no sockets are used."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


assistant = load("identity_assistant", "identity-map-assistant.py")
scanner = load("identity_scanner", "scan-linux-games.py")
WINDOWS_IDENTITY = r"C:\Games\Confirmed\game.exe"


class IdentityTools(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.prefix = self.work / "prefix with spaces"
        self.prefix.mkdir()
        self.owner = self.work / "verified runtime"
        self.owner.write_text("#!/bin/sh\nexit 0\n")
        self.owner.chmod(0o700)
        self.map = self.work / "games.map"

    def proc(self, prefix=True):
        return {"pid": 1234, "exe": str(self.owner), "kind": "wine" if prefix else "native",
                "sockets": [{"proto": "tcp", "local": "127.0.0.1:40000", "remote": "127.0.0.1:40001"}],
                "launcher": None, "suggested_source": "wineprefix:" + str(self.prefix) if prefix else str(self.owner),
                "steam_compat_data": None, "wine_prefix": str(self.prefix) if prefix else None}

    def run_assistant(self, args, proc=None):
        output, error = io.StringIO(), io.StringIO()
        with patch.object(assistant, "discover", return_value=[proc or self.proc()]), \
                patch.object(assistant, "windows_candidates", return_value=[]), \
                patch("sys.argv", ["identity-map-assistant", *args]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            status = assistant.main()
        return status, output.getvalue(), error.getvalue()

    def append_args(self, *extra, identity=WINDOWS_IDENTITY):
        return ["--pid", "1234", "--append", str(self.map), "--windows-identity", identity, *extra]

    def test_prefix_requires_explicit_owner_approval(self):
        status, _, error = self.run_assistant(self.append_args())
        self.assertEqual(status, 2)
        self.assertIn("require explicit --owner-exe", error)
        self.assertFalse(self.map.exists())

    def test_prefix_writes_three_fields_and_canonical_owner(self):
        alias = self.work / "owner alias"
        alias.symlink_to(self.owner)
        status, _, _ = self.run_assistant(self.append_args("--owner-exe", str(alias)))
        self.assertEqual(status, 0)
        lines = [line for line in self.map.read_text().splitlines() if not line.startswith("#")]
        self.assertEqual(lines, [f"wineprefix:{self.prefix}\t{WINDOWS_IDENTITY}\t{self.owner}"])

    def test_native_still_writes_two_fields(self):
        status, _, _ = self.run_assistant(self.append_args(), self.proc(prefix=False))
        self.assertEqual(status, 0)
        self.assertIn(f"{self.owner}\t{WINDOWS_IDENTITY}\n", self.map.read_text())

    def test_native_rejects_owner_column(self):
        status, _, error = self.run_assistant(self.append_args("--owner-exe", str(self.owner)), self.proc(prefix=False))
        self.assertEqual(status, 2)
        self.assertIn("only valid for a prefix", error)
        self.assertFalse(self.map.exists())

    def test_different_executable_cannot_be_approved_as_observed_owner(self):
        other = self.work / "other runtime"
        other.write_text("#!/bin/sh\nexit 0\n")
        other.chmod(0o700)
        status, _, error = self.run_assistant(self.append_args("--owner-exe", str(other)))
        self.assertEqual(status, 2)
        self.assertIn("must match the observed executable", error)
        self.assertFalse(self.map.exists())

    def test_invalid_owner_paths_are_rejected_without_writing(self):
        nonexec = self.work / "data"
        nonexec.write_text("not executable")
        loop = self.work / "loop"
        loop.symlink_to(loop)
        for owner in ("relative-runtime", self.work / "missing", self.prefix, nonexec, loop, "bad\0owner"):
            with self.subTest(owner=owner):
                status, _, _ = self.run_assistant(self.append_args("--owner-exe", str(owner)))
                self.assertEqual(status, 2)
                self.assertFalse(self.map.exists())

    def test_confirmed_identity_cannot_inject_map_rows_or_columns(self):
        for identity in ("C:\\game.exe\n/another/source\tC:\\other.exe", "C:\\game.exe\towner", "C:\\game.exe\r", "C:\\game.exe\0"):
            with self.subTest(identity=identity):
                status, _, _ = self.run_assistant(self.append_args(identity=identity), self.proc(prefix=False))
                self.assertEqual(status, 2)
                self.assertFalse(self.map.exists())

    def test_discovered_source_cannot_inject_map_fields(self):
        proc = self.proc(prefix=False)
        proc["suggested_source"] += "\nother"
        status, _, _ = self.run_assistant(self.append_args(), proc)
        self.assertEqual(status, 2)
        self.assertFalse(self.map.exists())

    def test_json_keeps_windows_identity_unconfirmed_and_owner_a_candidate(self):
        status, output, _ = self.run_assistant(["--json"])
        self.assertEqual(status, 0)
        report = json.loads(output)[0]
        self.assertIsNone(report["windows_identity"])
        self.assertEqual(report["owner_executable_candidate"], str(self.owner))
        self.assertFalse(self.map.exists())

    def test_repeating_same_confirmed_prefix_entry_is_idempotent(self):
        args = self.append_args("--owner-exe", str(self.owner))
        self.assertEqual(self.run_assistant(args)[0], 0)
        before = self.map.read_bytes()
        self.assertEqual(self.run_assistant(args)[0], 0)
        self.assertEqual(self.map.read_bytes(), before)

    def test_scanner_prefix_candidates_require_explicit_runtime_confirmation(self):
        output = io.StringIO()
        with patch.object(scanner, "steam_root", return_value=self.work), \
                patch.object(scanner, "library_paths", return_value=[self.work]), \
                patch.object(scanner, "installed_apps", return_value=[(12345, "Example", "Example", self.work)]), \
                patch.object(scanner, "compatdata_prefix", return_value=self.prefix), \
                patch.object(scanner, "has_windows_exe", return_value=None), \
                patch("sys.argv", ["scan-linux-games"]), \
                contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(scanner.main(), 0)
        rows = [line for line in output.getvalue().splitlines() if line.startswith("# wineprefix:")]
        self.assertEqual(len(rows), 1)
        self.assertEqual(len(rows[0].split("\t")), 3)
        self.assertEqual(rows[0].split("\t")[2], "<CONFIRM_RUNTIME_EXECUTABLE>")
        self.assertTrue(all(not line or line.startswith("#") for line in output.getvalue().splitlines()))


if __name__ == "__main__":
    unittest.main()
