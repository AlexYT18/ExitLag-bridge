#!/usr/bin/env python3
"""Account-free Linux supervisor and package-boundary checks."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('supervisor', ROOT / 'installers/linux/run_root.py')
module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)


class Supervisor(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.path = Path(self.temporary.name) / 'private'
        self.game = Path(self.temporary.name) / 'WowClassic.exe'
        self.game.write_text('#!/bin/sh\n')
        self.game.chmod(0o700)
        self.path.write_text(str(self.game) + '\tC:\\Games\\WowClassic.exe\n')
        self.path.chmod(0o600)

    def tearDown(self): self.temporary.cleanup()

    def test_map_is_data_not_a_root_command(self):
        text = module.read_map(self.path, os.getuid())
        self.assertIn('WowClassic.exe', text)
        for unsafe in ('relative\tC:\\Game.exe\n', '/game\tcommand\n', '/game\tC:\\Game.exe\0\n', '/game\tC:\\Game.exe\textra\n', '# empty\n'):
            self.path.write_text(unsafe)
            with self.assertRaises(ValueError): module.read_map(self.path, os.getuid())

    def test_map_links_public_files_and_other_owners_are_refused(self):
        with self.assertRaises(ValueError): module.read_map(self.path, os.getuid() + 1)
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): module.read_map(self.path, os.getuid())
        self.path.chmod(0o600)
        link = self.path.with_suffix('.link'); link.symlink_to(self.path)
        with self.assertRaises(OSError): module.read_map(link, os.getuid())

    def test_prefix_mapping_requires_actual_loader_third_column(self):
        prefix = Path(self.temporary.name) / 'game prefix'
        prefix.mkdir()
        mapping = f'wineprefix:{prefix}\tC:\\Games\\WowClassic.exe'
        self.path.write_text(mapping + '\n')
        with self.assertRaisesRegex(ValueError, 'OWNER_EXE third column'):
            module.read_map(self.path, os.getuid())
        self.path.write_text(mapping + '\t' + str(self.game) + '\n')
        self.assertEqual(module.read_map(self.path, os.getuid()), self.path.read_text())

    def test_prefix_owner_and_native_source_must_be_regular_executables(self):
        prefix = Path(self.temporary.name) / 'prefix'
        prefix.mkdir()
        for owner in ('relative-loader', str(prefix), str(self.game)):
            self.game.chmod(0o600)
            self.path.write_text(f'wineprefix:{prefix}\tC:\\Game.exe\t{owner}\n')
            with self.subTest(owner=owner), self.assertRaises(ValueError):
                module.read_map(self.path, os.getuid())
        self.path.write_text(str(self.game) + '\tC:\\Game.exe\n')
        with self.assertRaises(ValueError):
            module.read_map(self.path, os.getuid())

    def test_duplicate_canonical_mapping_is_rejected_but_distinct_loaders_work(self):
        prefix = Path(self.temporary.name) / 'prefix'
        prefix.mkdir()
        alias = Path(self.temporary.name) / 'loader-alias'
        alias.symlink_to(self.game)
        first = f'wineprefix:{prefix}\tC:\\Game.exe\t{self.game}\n'
        self.path.write_text(first + f'wineprefix:{prefix}\tC:\\Game.exe\t{alias}\n')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            module.read_map(self.path, os.getuid())
        alias.unlink()
        alias.write_text('#!/bin/sh\n'); alias.chmod(0o700)
        self.assertEqual(module.read_map(self.path, os.getuid()), self.path.read_text())

    def test_native_mapping_does_not_accept_extra_owner_column(self):
        self.path.write_text(str(self.game) + '\tC:\\Game.exe\t' + str(self.game) + '\n')
        with self.assertRaises(ValueError):
            module.read_map(self.path, os.getuid())

    def test_expired_or_removed_lease_stops_routing(self):
        self.path.write_text('run\n')
        self.assertTrue(module.lease_alive(self.path, os.getuid()))
        os.utime(self.path, (time.time() - 10, time.time() - 10))
        self.assertFalse(module.lease_alive(self.path, os.getuid()))
        self.path.touch(); self.path.write_text('arbitrary command\n')
        self.assertFalse(module.lease_alive(self.path, os.getuid()))
        self.path.unlink()
        self.assertFalse(module.lease_alive(self.path, os.getuid()))

    def test_lease_timestamp_boundaries_reject_future_and_expired_records(self):
        self.path.write_text('run\n')
        for stamp, expected in ((1000, True), (994.001, True), (994, False), (1000.001, False), (2000, False)):
            with self.subTest(stamp=stamp), mock.patch.object(module.time, 'time', return_value=1000):
                os.utime(self.path, (stamp, stamp))
                self.assertEqual(module.lease_alive(self.path, os.getuid()), expected)

    def test_lease_requires_private_regular_single_link_file(self):
        self.path.write_text('run\n')
        self.assertFalse(module.lease_alive(self.path, os.getuid() + 1))
        self.path.chmod(0o644)
        self.assertFalse(module.lease_alive(self.path, os.getuid()))
        self.path.chmod(0o600)
        link = self.path.with_suffix('.link')
        os.link(self.path, link)
        self.assertFalse(module.lease_alive(self.path, os.getuid()))
        link.unlink()
        self.path.unlink()
        os.mkfifo(self.path, 0o600)
        self.assertFalse(module.lease_alive(self.path, os.getuid()))

    @unittest.skipUnless(sys.platform == 'linux', 'Linux /proc identity')
    def test_parent_identity_includes_owner_and_start_time(self):
        owner, started = module.process_identity(os.getpid())
        self.assertEqual(owner, os.getuid()); self.assertTrue(started.isdecimal())

    def test_uninstalled_privileged_entry_refuses_to_run(self):
        args = ['run_root', '--uid', str(os.getuid()), '--parent', str(os.getpid()), '--map', str(self.path), '--lease', str(self.path)]
        with mock.patch.object(sys, 'argv', args), mock.patch.object(os, 'geteuid', return_value=0):
            with self.assertRaisesRegex(SystemExit, 'installed'):
                module.main()


if __name__ == '__main__': unittest.main(verbosity=2)
