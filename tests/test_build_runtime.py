#!/usr/bin/env python3
"""Account-free LLVM payload orchestration and compiler cache tests."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installers'))
SPEC = importlib.util.spec_from_file_location('runtime_builder_tests', ROOT / 'installers/build_runtime.py')
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class RuntimeBuild(unittest.TestCase):
    def test_llvm_dependency_check_lists_missing_tools(self):
        with mock.patch.object(builder.shutil, 'which', side_effect=lambda name: None if name in ('llvm-rc', 'lld-link') else '/tools/' + name):
            with self.assertRaisesRegex(RuntimeError, 'lld-link, llvm-rc'):
                builder.llvm_tools()

    def test_llvm_identity_changes_when_compiler_changes_at_same_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            tool = Path(temporary) / 'clang'
            tool.write_bytes(b'compiler revision one')
            before = builder.compiler_identity(None, {'clang': str(tool)})
            tool.write_bytes(b'compiler revision two')
            after = builder.compiler_identity(None, {'clang': str(tool)})
            self.assertNotEqual(before, after)
            self.assertEqual(before['clang']['path'], after['clang']['path'])

    def test_zig_identity_preserves_pinned_version(self):
        self.assertEqual(builder.compiler_identity(Path('/tools/zig'), None),
                         {'zig': {'path': '/tools/zig', 'version': '0.17.0'}})

    def test_llvm_payloads_use_native_scripts_and_only_required_linux_components(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'payloads'
            for name, directory in (('nfapi.dll', 'nfapi'), ('nfextlag.sys', 'nfextlag')):
                path = root / 'shim' / directory / 'build' / name
                path.parent.mkdir(parents=True)
                path.write_bytes(b'synthetic build fixture ' + name.encode())
            commands = []
            def wmi(zig, target, llvm=None):
                self.assertIsNone(zig)
                self.assertEqual(llvm, {'clang': '/tools/clang'})
                target.write_bytes(b'synthetic WMI build fixture')
                return root / 'corresponding-source.tar.gz'
            with mock.patch.object(builder, 'REPO', root), \
                    mock.patch.object(builder, 'BUILD', root / 'build'), \
                    mock.patch.object(builder, 'llvm_tools', return_value={'clang': '/tools/clang'}), \
                    mock.patch.object(builder, 'zig_tool', side_effect=AssertionError('Zig downloaded')), \
                    mock.patch.object(builder, 'run', side_effect=lambda args, **kwargs: commands.append(args)), \
                    mock.patch.object(builder, 'build_wmi', side_effect=wmi), \
                    mock.patch.object(builder, 'build_linux_nfapi') as package_shim, \
                    mock.patch.object(builder, 'verify_linux_exports') as exports, \
                    mock.patch.object(builder.sys, 'platform', 'linux'), \
                    mock.patch.object(sys, 'argv', ['build_runtime.py', 'payloads', '--toolchain', 'llvm', '--arch', 'x86_64', '--output', str(output)]), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                builder.main()
            self.assertTrue(json.loads(stdout.getvalue())['payloads_ready'])
            self.assertEqual(commands, [['bash', root / 'shim/nfapi/build.sh'],
                                        ['bash', root / 'shim/nfextlag/build.sh']])
            package_shim.assert_called_once_with({'clang': '/tools/clang'}, output / 'nfapi.dll')
            manifest = json.loads((output / 'manifest.json').read_text())
            self.assertEqual(set(manifest['files']), {'nfapi.dll', 'nfextlag.sys', 'wbemprox.dll'})
            for name, digest in manifest['files'].items():
                self.assertEqual(builder.digest(output / name), digest)
            self.assertFalse((output / 'WowClassic.exe').exists())

    def test_linux_packaged_shim_keeps_registration_abi_with_normal_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(builder, 'BUILD', Path(temporary)), \
                mock.patch.object(builder, 'run') as run:
            builder.build_linux_nfapi({'llvm-dlltool': 'dlltool', 'clang': 'clang',
                                       'lld-link': 'lld-link'}, Path(temporary) / 'nfapi.dll')
            compile_command = run.call_args_list[1].args[0]
            self.assertIn('driver-registration.cpp', compile_command)
            link_command = run.call_args_list[2].args[0]
            self.assertIn('/entry:DllMain', link_command)
            self.assertNotIn('/entry:MacDllMain', link_command)
            self.assertIn(Path(temporary) / 'linux-payloads/driver-registration.obj', link_command)

    def test_packaged_export_check_requires_core_and_both_driver_names_exactly(self):
        core = {'core-function'}
        expected = core | {'?nf_registerDriver@nfapi@@YA?AW4_NF_STATUS@@PEBD@Z',
                           '?nf_unRegisterDriver@nfapi@@YA?AW4_NF_STATUS@@PEBD@Z'}
        for provided, valid in ((expected, True), (core, False),
                                (expected | {'unexpected'}, False),
                                (expected - core, False)):
            with self.subTest(provided=provided), mock.patch.object(builder, 'PE') as parser:
                parser.side_effect = [mock.Mock(exported_names=lambda: core),
                                      mock.Mock(exported_names=lambda: provided)]
                if valid:
                    builder.verify_linux_exports('core.dll', 'package.dll')
                else:
                    with self.assertRaisesRegex(RuntimeError, 'exports differ'):
                        builder.verify_linux_exports('core.dll', 'package.dll')

    def test_unsupported_llvm_host_is_refused_before_compilation(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(builder, 'BUILD', Path(temporary) / 'build'), \
                mock.patch.object(builder.sys, 'platform', 'darwin'), \
                mock.patch.object(sys, 'argv', ['build_runtime.py', 'payloads', '--toolchain', 'llvm', '--arch', 'x86_64', '--output', str(Path(temporary) / 'out')]), \
                mock.patch.object(builder, 'llvm_tools') as tools, \
                contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as failure:
                builder.main()
            self.assertEqual(failure.exception.code, 2)
            tools.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
