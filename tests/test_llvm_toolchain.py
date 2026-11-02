#!/usr/bin/env python3
"""Compiler selection negatives need no compiler, Wine, account or network."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ClDriverSelection(unittest.TestCase):
    def select(self, tools):
        with tempfile.TemporaryDirectory(prefix='exl-toolchain-') as work:
            for tool in tools:
                path = Path(work) / tool
                path.write_text('#!/bin/sh\nexit 0\n')
                path.chmod(0o755)
            environment = dict(os.environ, PATH=work)
            return subprocess.run([
                '/bin/bash', '-ec',
                'source "$1/shim/llvm-toolchain.sh"; printf "%s\\n" "${EXITLAG_CL_DRIVER[@]}"',
                'fixture', str(ROOT),
            ], env=environment, capture_output=True, text=True, check=False)

    def test_cl_alias_is_preferred_when_both_drivers_exist(self):
        result = self.select(('clang', 'clang-cl'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['clang-cl'])

    def test_plain_clang_uses_explicit_cl_driver_mode(self):
        result = self.select(('clang',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['clang', '--driver-mode=cl'])

    def test_missing_both_drivers_is_a_clear_failure(self):
        result = self.select(())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PE build requires', result.stderr)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main(verbosity=2)
