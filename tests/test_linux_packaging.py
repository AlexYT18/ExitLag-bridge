#!/usr/bin/env python3
"""Account-free packaging fixtures; no vendor client, Wine runtime or root.

The tiny fixture files are not executable bridge artifacts and are never
published. These tests verify the installer layout and packaging boundaries.
"""
import contextlib
from email.parser import Parser
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('linux_package_builder', ROOT / 'installers/linux/build.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class LinuxPackaging(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='bridge-package-test-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.source = self.work / 'source'
        self.output = self.work / 'output'
        for name in builder.FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture only: ' + name + '\n')
        for name in ('installers/bridge_setup/__init__.py',
                     'installers/bridge_setup/core.py',
                     'installers/bridge_setup/process_picker.py',
                     'installers/payloads/manifest.json',
                     'installers/payloads/nfapi.dll',
                     'LICENSES/fixture-notice', 'macos/app/BridgeIcon.svg',
                     'installers/linux/install.sh', 'installers/linux/uninstall.sh'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture only: ' + name + '\n')
        # A developer tree can contain private runtime/account material, but
        # explicit program packaging must not collect that tree wholesale.
        for name in ('runtime/prefix/drive_c/ExitLag/ExitLag.exe',
                     'runtime/private-account', '.env', 'unrelated.exe',
                     'installers/bridge_setup/__pycache__/cache.pyc'):
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'private-fixture-canary')
        patcher = mock.patch.object(builder, 'ROOT', self.source)
        patcher.start()
        self.addCleanup(patcher.stop)

    @property
    def archive(self):
        return self.output / f'exitlag-bridge-{builder.VERSION}-linux-x86_64.tar.gz'

    def run_builder(self, *arguments):
        with mock.patch.object(sys, 'argv', ['build.py', '--output', str(self.output), *arguments]), \
                mock.patch.object(builder.sys, 'platform', 'linux'), \
                mock.patch.object(builder.platform, 'machine', return_value='x86_64'), \
                contextlib.redirect_stdout(io.StringIO()) as stream:
            builder.main()
        return json.loads(stream.getvalue())

    def test_population_includes_process_picker_and_dependencies(self):
        target = self.work / 'program'
        builder.populate(target)
        for name in ('installers/linux/game_picker.py',
                     'backend/run-udp-multi.sh',
                     'tools/discover-game-processes.py',
                     'installers/bridge_setup/process_picker.py',
                     'installers/bridge_setup/core.py',
                     'installers/linux/run_root.py',
                     'backend/exitlag-netd', 'LICENSE', 'THIRD_PARTY.md'):
            with self.subTest(name=name):
                self.assertEqual((target / name).read_bytes(), (self.source / name).read_bytes())
        self.assertEqual((target / '.exitlag-bridge-program').read_text(), builder.VERSION + '\n')
        self.assertFalse((target / 'runtime').exists())
        self.assertFalse((target / '.env').exists())
        self.assertFalse((target / 'unrelated.exe').exists())
        self.assertFalse((target / 'installers/bridge_setup/__pycache__').exists())
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o755)
        for path in target.rglob('*'):
            with self.subTest(mode=str(path.relative_to(target))):
                expected = 0o755 if path.is_dir() or path.suffix == '.sh' or path.name == 'exitlag-netd' else 0o644
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), expected)
                self.assertFalse(path.is_symlink())

    def test_missing_picker_dependency_prevents_packaging(self):
        (self.source / 'tools/discover-game-processes.py').unlink()
        with self.assertRaises(FileNotFoundError):
            builder.populate(self.work / 'program')

    def test_portable_only_never_invokes_debian_tools_and_has_complete_archive(self):
        with mock.patch.object(builder.subprocess, 'check_output', side_effect=AssertionError('dpkg invoked')), \
                mock.patch.object(builder.subprocess, 'run', side_effect=AssertionError('dpkg-deb invoked')):
            result = self.run_builder('--portable-only')
        self.assertTrue(result['packages_built'])
        self.assertFalse(result['proprietary_client_included'])
        self.assertTrue(self.archive.is_file())
        self.assertFalse(list(self.output.glob('*.deb')))
        with tarfile.open(self.archive, 'r:gz') as archive:
            members = {member.name: member for member in archive.getmembers()}
            top = f'exitlag-bridge-{builder.VERSION}-linux-x86_64'
            for name in ('install.sh', 'uninstall.sh', 'exitlag-bridge.desktop',
                         'program/backend/run-udp-multi.sh',
                         'program/installers/linux/game_picker.py',
                         'program/installers/bridge_setup/process_picker.py',
                         'program/tools/discover-game-processes.py'):
                self.assertIn(top + '/' + name, members)
            self.assertEqual(members[top].mode, 0o755)
            self.assertEqual(members[top + '/program'].mode, 0o755)
            self.assertEqual(members[top + '/install.sh'].mode, 0o755)
            self.assertEqual(members[top + '/uninstall.sh'].mode, 0o755)
            self.assertEqual(members[top + '/exitlag-bridge.desktop'].mode, 0o644)
            desktop = archive.extractfile(top + '/exitlag-bridge.desktop').read().decode()
            self.assertIn('/usr/local/lib/exitlag-bridge/installers/linux/app.py', desktop)
            self.assertIn('--manage-games', desktop)
            for member in members.values():
                self.assertTrue(member.isfile() or member.isdir())
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime),
                                 (0, 0, 'root', 'root', 0))
                if member.isfile():
                    self.assertNotIn(b'private-fixture-canary', archive.extractfile(member).read())
        hashes = json.loads((self.output / 'SHA256SUMS.json').read_text())
        self.assertEqual(hashes, {self.archive.name: hashlib.sha256(self.archive.read_bytes()).hexdigest()})

    def test_default_build_retains_debian_metadata_and_portable_output(self):
        inspected = []

        def check_deb(command, **options):
            self.assertEqual(command[:3], ['dpkg-deb', '--root-owner-group', '--build'])
            self.assertTrue(options['check'])
            staging, output = Path(command[3]), Path(command[4])
            control = (staging / 'DEBIAN/control').read_text()
            fields = Parser().parsestr(control)
            self.assertEqual(fields['Package'], 'exitlag-bridge')
            self.assertEqual(fields['Version'], builder.VERSION)
            self.assertEqual(fields['Architecture'], 'amd64')
            self.assertIn('python3', fields['Depends'])
            self.assertIsNotNone(fields['Description'])
            self.assertIn('proprietary client', fields['Description'])
            self.assertFalse(control.endswith('\n    '))
            self.assertTrue((staging / 'usr/lib/exitlag-bridge/installers/linux/game_picker.py').is_file())
            prerm = staging / 'DEBIAN/prerm'
            self.assertTrue(prerm.read_text().startswith('#!/bin/sh\nset -eu\n'))
            self.assertEqual(stat.S_IMODE(prerm.stat().st_mode), 0o755)
            output.write_bytes(b'fixture-deb-not-a-release')
            inspected.append(command)

        with mock.patch.object(builder.subprocess, 'check_output', return_value='amd64\n') as architecture, \
                mock.patch.object(builder.subprocess, 'run', side_effect=check_deb):
            self.run_builder()
        architecture.assert_called_once_with(['dpkg', '--print-architecture'], text=True)
        self.assertEqual(len(inspected), 1)
        self.assertTrue(self.archive.is_file())
        self.assertTrue((self.output / f'exitlag-bridge_{builder.VERSION}_amd64.deb').is_file())

    @unittest.skipUnless(shutil.which('dpkg-deb'), 'dpkg-deb is absent; portable fixtures still run')
    def test_real_dpkg_deb_accepts_fixture_metadata_without_root(self):
        # Exercise the real serializer with harmless fixtures, then inspect
        # fields using Debian's parser. The fixture package stays in tempdir.
        with mock.patch.object(builder.subprocess, 'check_output', return_value='amd64\n'):
            self.run_builder()
        package = self.output / f'exitlag-bridge_{builder.VERSION}_amd64.deb'
        actual = subprocess.check_output(['dpkg-deb', '--field', str(package), 'Package', 'Architecture'], text=True)
        self.assertIn('Package: exitlag-bridge', actual)
        self.assertIn('Architecture: amd64', actual)

    def test_private_umask_does_not_make_installed_program_unreadable(self):
        previous = os.umask(0o077)
        try:
            with mock.patch.object(builder.subprocess, 'check_output', side_effect=AssertionError('dpkg invoked')):
                self.run_builder('--portable-only')
        finally:
            os.umask(previous)
        with tarfile.open(self.archive, 'r:gz') as archive:
            for member in archive.getmembers():
                if member.isdir():
                    self.assertEqual(member.mode, 0o755, member.name)
                elif member.name.endswith('.desktop') or member.name.endswith('.py'):
                    self.assertEqual(member.mode, 0o644, member.name)

    def test_unsupported_host_is_refused_before_staging_or_tools(self):
        cases = (('linux', 'aarch64'), ('darwin', 'x86_64'), ('win32', 'AMD64'))
        for host, architecture in cases:
            with self.subTest(host=host, architecture=architecture), \
                    mock.patch.object(sys, 'argv', ['build.py', '--output', str(self.output), '--portable-only']), \
                    mock.patch.object(builder.sys, 'platform', host), \
                    mock.patch.object(builder.platform, 'machine', return_value=architecture), \
                    mock.patch.object(builder.subprocess, 'check_output') as check_output, \
                    mock.patch.object(builder.subprocess, 'run') as run, \
                    contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    builder.main()
                self.assertEqual(raised.exception.code, 2)
                check_output.assert_not_called()
                run.assert_not_called()
                self.assertFalse(self.output.exists())
                self.assertFalse((self.source / 'build').exists())

    def test_default_debian_architecture_validation_is_preserved(self):
        with mock.patch.object(sys, 'argv', ['build.py', '--output', str(self.output)]), \
                mock.patch.object(builder.sys, 'platform', 'linux'), \
                mock.patch.object(builder.platform, 'machine', return_value='x86_64'), \
                mock.patch.object(builder.subprocess, 'check_output', return_value='arm64\n'), \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                builder.main()
        self.assertEqual(raised.exception.code, 2)
        self.assertFalse(self.output.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
