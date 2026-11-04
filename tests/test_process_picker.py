#!/usr/bin/env python3
"""Unprivileged picker policy tests using bounded proc fixtures and real sockets."""
from dataclasses import replace
import os
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installers'))
from bridge_setup import process_picker as model

DISCOVERY = ROOT / 'tools/discover-game-processes.py'
IDENTITY = r'C:\Games\Confirmed\game.exe'


def pe_file(path, machine=0x8664, magic=0x20b):
    data = bytearray(512)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 60, 64)
    data[64:68] = b'PE\0\0'
    struct.pack_into('<HH', data, 68, machine, 1)
    struct.pack_into('<HHH', data, 84, 240, 2, magic)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


class Fixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='picker-test-')
        self.addCleanup(temporary.cleanup)
        self.work = Path(temporary.name)
        self.proc = self.work / 'proc'
        (self.proc / 'net').mkdir(parents=True)
        for name in ('tcp', 'tcp6', 'udp', 'udp6'):
            (self.proc / 'net' / name).write_text('sl local remote state queues timer retransmit uid timeout inode\n')
        self.pid = 1234
        self.process = self.proc / str(self.pid)
        (self.process / 'fd').mkdir(parents=True)
        self.owner = self.work / 'runtime with spaces'
        self.owner.write_text('#!/bin/sh\n')
        self.owner.chmod(0o700)
        (self.process / 'exe').symlink_to(self.owner)
        self.prefix = self.work / 'steamapps/compatdata/3527290/pfx'
        (self.prefix / 'drive_c').mkdir(parents=True)
        (self.prefix / 'dosdevices').mkdir()
        (self.prefix / 'dosdevices/c:').symlink_to('../drive_c')
        (self.prefix / 'dosdevices/z:').symlink_to('/')
        self.write_stat()
        self.write_uids()
        (self.process / 'comm').write_text('Selected Game.exe\n')
        (self.process / 'maps').write_text('')
        (self.process / 'cmdline').write_bytes(b'C:\\Invented\\NotProof.exe\0')
        self.write_environment()
        self.add_socket('tcp', 1001, 3)
        self.add_socket('udp', 1002, 4)
        self.picker = model.ProcessPicker(DISCOVERY, self.proc)

    def write_stat(self, birth=777, pid=None):
        fields = ['S'] + ['0'] * 18 + [str(birth)] + ['0'] * 30
        (self.process / 'stat').write_text(f'{pid or self.pid} (name with ) parentheses) ' + ' '.join(fields) + '\n')

    def write_uids(self, values=None):
        values = values if values is not None else [os.getuid()] * 4
        (self.process / 'status').write_text('Name:\tSelected Game.exe\nUid:\t' + '\t'.join(map(str, values)) + '\n')

    def write_environment(self, **changes):
        values = {'WINEPREFIX': str(self.prefix), 'STEAM_COMPAT_DATA_PATH': str(self.prefix.parent),
                  'SteamAppId': '3527290', 'PRIVATE_TEST_SECRET': 'must-not-be-returned'}
        values.update(changes)
        (self.process / 'environ').write_bytes(b'\0'.join(
            f'{key}={value}'.encode() for key, value in values.items() if value is not None) + b'\0')

    def add_socket(self, protocol, inode, descriptor):
        v6 = protocol.endswith('6')
        endpoint = ('00000000000000000000000001000000' if v6 else '0100007F') + ':9C40'
        row = f'0: {endpoint} {endpoint} 01 0:0 0:0 0 {os.getuid()} 0 {inode}\n'
        with (self.proc / 'net' / protocol).open('a') as output:
            output.write(row)
        (self.process / 'fd' / str(descriptor)).symlink_to(f'socket:[{inode}]')

    def candidate(self):
        candidates = self.picker.list_candidates()
        self.assertEqual(len(candidates), 1)
        return candidates[0]

    def map_image(self, path, inode=None, device=None):
        info = path.stat()
        device = info.st_dev if device is None else device
        inode = info.st_ino if inode is None else inode
        with (self.process / 'maps').open('a') as output:
            output.write(f'100000-101000 r-xp 00000000 {os.major(device):x}:{os.minor(device):x} {inode} {path}\n')

    def test_proton_candidate_contains_verified_owner_socket_protocols_and_generation(self):
        candidate = self.candidate()
        self.assertEqual((candidate.pid, candidate.uid, candidate.start_time), (self.pid, os.getuid(), 777))
        self.assertEqual((candidate.executable, candidate.prefix), (self.owner, self.prefix))
        self.assertEqual(candidate.kind, 'proton')
        self.assertEqual(candidate.transports, ('tcp', 'udp'))
        self.assertEqual((candidate.socket_count, candidate.inodes), (2, (1001, 1002)))
        self.assertEqual(candidate.steam_appid, '3527290')
        self.assertNotIn('must-not-be-returned', repr(candidate))
        self.picker.revalidate(candidate)

    def test_native_selection_writes_two_fields_after_explicit_identity(self):
        self.write_environment(WINEPREFIX=None, STEAM_COMPAT_DATA_PATH=None, SteamAppId=None)
        candidate = self.candidate()
        self.assertEqual(candidate.kind, 'native')
        self.assertIsNone(candidate.prefix)
        self.assertEqual(self.picker.windows_images(candidate), [])
        self.assertEqual(self.picker.mapping(candidate, windows_identity=IDENTITY),
                         f'{self.owner}\t{IDENTITY}\n')

    def test_wine_selection_writes_exact_prefix_and_owner(self):
        self.write_environment(STEAM_COMPAT_DATA_PATH=None)
        candidate = self.candidate()
        self.assertEqual(candidate.kind, 'wine')
        self.assertEqual(self.picker.mapping(candidate, windows_identity=IDENTITY),
                         f'wineprefix:{self.prefix}\t{IDENTITY}\t{self.owner}\n')

    def test_compat_data_without_observed_wineprefix_cannot_authorize_prefix(self):
        self.write_environment(WINEPREFIX=None)
        candidate = self.candidate()
        self.assertEqual(candidate.kind, 'proton')
        with self.assertRaisesRegex(model.PickerError, 'WINEPREFIX'):
            self.picker.mapping(candidate, windows_identity=IDENTITY)

    def test_argv_is_never_a_windows_image_or_mapping_identity(self):
        candidate = self.candidate()
        self.assertEqual(self.picker.windows_images(candidate), [])
        with self.assertRaises(model.PickerError):
            self.picker.mapping(candidate)

    def test_display_name_sanitizes_control_characters(self):
        (self.process / 'comm').write_text('Game\tname\nspoof\x7f\n')
        self.assertEqual(self.candidate().name, 'Game name spoof ')

    def test_different_credentials_and_different_proc_owner_are_excluded(self):
        candidate = self.candidate()
        self.write_uids([os.getuid(), os.getuid() + 1, os.getuid(), os.getuid()])
        self.assertEqual(self.picker.list_candidates(), [])
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)
        self.write_uids()
        self.assertEqual(model.ProcessPicker(DISCOVERY, self.proc, uid=os.getuid() + 1).list_candidates(), [])

    def test_pid_reuse_and_exit_invalidate_selection(self):
        candidate = self.candidate()
        self.write_stat(birth=778)
        with self.assertRaises(model.PickerError):
            self.picker.mapping(candidate, windows_identity=IDENTITY)
        shutil.rmtree(self.process)
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)

    def test_executable_replacement_at_same_path_invalidates_selection(self):
        candidate = self.candidate()
        replacement = self.work / 'replacement'
        replacement.write_text('#!/bin/sh\nexit 1\n')
        replacement.chmod(0o700)
        replacement.replace(self.owner)
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)

    def test_exec_to_another_path_invalidates_selection(self):
        candidate = self.candidate()
        other = self.work / 'another runtime'
        other.write_text('#!/bin/sh\n')
        other.chmod(0o700)
        (self.process / 'exe').unlink()
        (self.process / 'exe').symlink_to(other)
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)

    def test_prefix_replacement_or_changed_environment_invalidates_selection(self):
        candidate = self.candidate()
        self.prefix.rename(self.prefix.with_name('old-prefix'))
        self.prefix.mkdir()
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)
        candidate = self.candidate()
        other = self.work / 'other prefix'
        other.mkdir()
        self.write_environment(WINEPREFIX=str(other))
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)

    def test_a_remaining_original_socket_is_required(self):
        candidate = self.candidate()
        (self.process / 'fd/3').unlink()
        self.picker.revalidate(candidate)
        (self.process / 'fd/4').unlink()
        self.add_socket('tcp', 2003, 5)
        with self.assertRaises(model.PickerError):
            self.picker.revalidate(candidate)

    def test_process_changing_during_fd_snapshot_is_not_returned(self):
        original = self.picker._held
        def changing(*arguments):
            result = original(*arguments)
            self.write_stat(birth=778)
            return result
        with mock.patch.object(self.picker, '_held', side_effect=changing):
            self.assertEqual(self.picker.list_candidates(), [])

    def test_bad_or_conflicting_appids_are_only_discarded_display_hints(self):
        for value, other in (('1', None), ('not-an-id', None), ('0', None),
                             (str(2**32), None), ('3527290', '2222')):
            with self.subTest(value=value, other=other):
                self.write_environment(SteamAppId=value, STEAM_COMPAT_APP_ID=other)
                candidate = self.candidate()
                self.assertIsNone(candidate.steam_appid)
                self.assertEqual(candidate.prefix, self.prefix)

    def test_malformed_birth_and_status_records_are_not_candidates(self):
        for value in ('-1', '0', str(2**64), 'x'):
            self.write_stat(birth=value)
            self.assertEqual(self.picker.list_candidates(), [])
        self.write_stat()
        (self.process / 'status').write_text('Uid:\t1\t2\n')
        self.assertEqual(self.picker.list_candidates(), [])
        self.write_uids()
        with (self.process / 'status').open('a') as output:
            output.write('Uid:\t0\t0\t0\t0\n')
        self.assertEqual(self.picker.list_candidates(), [])

    def test_env_conflicts_are_rejected_and_unknown_secrets_not_exposed(self):
        with (self.process / 'environ').open('ab') as output:
            output.write(b'WINEPREFIX=/different/prefix\0')
        self.assertEqual(self.picker.list_candidates(), [])
        self.assertEqual(model._environment(b'SECRET=private\0SteamAppId=23\0'), {'SteamAppId': '23'})

    def test_scan_read_and_descriptor_limits_fail_safely(self):
        candidate = self.candidate()
        with mock.patch.object(model, 'MAX_PROCESSES', 0):
            with self.assertRaisesRegex(model.PickerError, 'scan limit'):
                self.picker.list_candidates()
        with mock.patch.object(model, 'MAX_FILE', 8):
            with self.assertRaisesRegex(model.PickerError, 'read limit'):
                self.picker.list_candidates()
        with mock.patch.object(model, 'MAX_ENV', 8):
            self.assertEqual(self.picker.list_candidates(), [])
        with mock.patch.object(model, 'MAX_FDS', 1):
            with self.assertRaises(model.PickerError):
                self.picker.revalidate(candidate)

    def test_missing_network_tables_are_reported_instead_of_empty_success(self):
        for path in (self.proc / 'net').iterdir():
            path.unlink()
        with self.assertRaisesRegex(model.PickerError, 'unavailable'):
            self.picker.list_candidates()

    def test_missing_discovery_component_is_reported_as_picker_error(self):
        with self.assertRaisesRegex(model.PickerError, 'component is unavailable'):
            model.ProcessPicker(self.work / 'missing-discovery.py', self.proc)

    def test_symlink_loop_in_prefix_is_not_a_candidate(self):
        loop = self.work / 'prefix-loop'
        loop.symlink_to(loop)
        self.write_environment(WINEPREFIX=str(loop))
        self.assertEqual(self.picker.list_candidates(), [])

    def test_conflicting_socket_inode_records_are_rejected(self):
        self.add_socket('udp', 1001, 5)
        with self.assertRaisesRegex(model.PickerError, 'Conflicting'):
            self.picker.list_candidates()

    def test_ipv6_socket_is_attributed_and_malformed_rows_are_ignored(self):
        self.add_socket('tcp6', 1003, 6)
        with (self.proc / 'net/tcp').open('a') as output:
            output.write('broken row\n0: NOTHEX:0010 0100007F:0010 01 0:0 0:0 0 0 0 7777\n')
        self.assertEqual(self.candidate().inodes, (1001, 1002, 1003))

    def test_mapped_pe_is_offered_using_verified_longest_drive_root(self):
        image = pe_file(self.prefix / 'drive_c/Games/Selected Game.exe')
        self.map_image(image)
        choices = self.picker.windows_images(self.candidate())
        self.assertEqual(len(choices), 1)
        self.assertTrue(choices[0].observed)
        self.assertEqual(choices[0].windows_path, r'C:\Games\Selected Game.exe')
        self.assertEqual(self.picker.mapping(self.candidate(), image=choices[0]),
                         f'wineprefix:{self.prefix}\tC:\\Games\\Selected Game.exe\t{self.owner}\n')

    def test_explicit_game_file_uses_actual_z_drive_and_requires_no_wine_execution(self):
        image = pe_file(self.work / 'Steam Library/My Game/Selected Game.exe')
        candidate = self.candidate()
        choice = self.picker.image_from_file(candidate, image)
        self.assertFalse(choice.observed)
        self.assertEqual(choice.windows_path, 'Z:' + str(image).replace('/', '\\'))
        self.assertIn(choice.windows_path, self.picker.mapping(candidate, image=choice))

    def test_unrelated_broken_removable_drive_does_not_hide_valid_c_game(self):
        (self.prefix / 'dosdevices/d:').symlink_to(self.work / 'disconnected-drive')
        loop = self.prefix / 'dosdevices/e:'
        loop.symlink_to(loop)
        image = pe_file(self.prefix / 'drive_c/game.exe')
        self.assertEqual(self.picker.image_from_file(self.candidate(), image).windows_path, r'C:\game.exe')

    def test_file_not_reachable_through_verified_drive_is_rejected(self):
        (self.prefix / 'dosdevices/z:').unlink()
        image = pe_file(self.work / 'outside.exe')
        with self.assertRaises(model.PickerError):
            self.picker.image_from_file(self.candidate(), image)

    def test_non_symlink_drive_and_conflicting_drive_case_alias_fail_safely(self):
        image = pe_file(self.work / 'outside.exe')
        (self.prefix / 'dosdevices/z:').unlink()
        (self.prefix / 'dosdevices/z:').write_text('/')
        with self.assertRaises(model.PickerError):
            self.picker.image_from_file(self.candidate(), image)
        (self.prefix / 'dosdevices/C:').symlink_to(self.work)
        with self.assertRaisesRegex(model.PickerError, 'Conflicting'):
            self.picker.image_from_file(self.candidate(), image)

    def test_map_path_without_matching_kernel_device_inode_is_not_observed(self):
        image = pe_file(self.prefix / 'drive_c/game.exe')
        self.map_image(image, inode=image.stat().st_ino + 1)
        self.assertEqual(self.picker.windows_images(self.candidate()), [])
        self.assertFalse(self.picker.image_from_file(self.candidate(), image).observed)

    def test_replaced_map_path_cannot_be_mislabeled_as_observed(self):
        image = pe_file(self.prefix / 'drive_c/game.exe')
        self.map_image(image)
        replacement = pe_file(self.work / 'replacement.exe')
        replacement.replace(image)
        self.assertEqual(self.picker.windows_images(self.candidate()), [])

    def test_deleted_and_non_executable_map_entries_are_ignored(self):
        image = pe_file(self.prefix / 'drive_c/game.exe')
        self.map_image(image)
        maps = self.process / 'maps'
        maps.write_text(maps.read_text().rstrip() + ' (deleted)\n')
        self.assertEqual(self.picker.windows_images(self.candidate()), [])

    def test_malformed_pe_variants_are_rejected(self):
        image = self.prefix / 'drive_c/game.exe'
        base = pe_file(image).read_bytes()
        variants = []
        for offset, replacement in ((0, b'NO'), (64, b'NOPE'), (68, struct.pack('<H', 0)),
                                    (70, struct.pack('<H', 0)), (86, struct.pack('<H', 0x2002)),
                                    (88, struct.pack('<H', 0x10b)), (84, struct.pack('<H', 0xffff)),
                                    (60, struct.pack('<I', 2**32 - 1))):
            value = bytearray(base)
            value[offset:offset + len(replacement)] = replacement
            variants.append(value)
        variants.extend((b'MZ', base[:90]))
        candidate = self.candidate()
        for value in variants:
            image.write_bytes(value)
            with self.subTest(length=len(value), header=bytes(value[:2])):
                with self.assertRaises(model.PickerError):
                    self.picker.image_from_file(candidate, image)

    def test_pe32_executable_is_supported(self):
        image = pe_file(self.prefix / 'drive_c/game.exe', machine=0x14c, magic=0x10b)
        self.assertEqual(self.picker.image_from_file(self.candidate(), image).windows_path, r'C:\game.exe')

    def test_modified_selected_file_or_changed_drive_requires_reselection(self):
        image = pe_file(self.prefix / 'drive_c/game.exe')
        candidate = self.candidate()
        choice = self.picker.image_from_file(candidate, image)
        image.write_bytes(image.read_bytes() + b'new bytes')
        with self.assertRaises(model.PickerError):
            self.picker.mapping(candidate, image=choice)
        choice = self.picker.image_from_file(candidate, image)
        (self.prefix / 'dosdevices/c:').unlink()
        (self.prefix / 'dosdevices/c:').symlink_to(self.work)
        with self.assertRaises(model.PickerError):
            self.picker.mapping(candidate, image=choice)

    def test_an_observed_image_must_remain_mapped_at_add_time(self):
        image = pe_file(self.prefix / 'drive_c/game.exe')
        self.map_image(image)
        candidate = self.candidate()
        choice, = self.picker.windows_images(candidate)
        (self.process / 'maps').write_text('')
        with self.assertRaisesRegex(model.PickerError, 'no longer mapped'):
            self.picker.mapping(candidate, image=choice)

    def test_many_images_have_bounded_socket_table_rescans(self):
        for i in range(8):
            image = pe_file(self.prefix / f'drive_c/game{i}.exe')
            self.map_image(image)
        candidate = self.candidate()
        with mock.patch.object(self.picker, '_network', wraps=self.picker._network) as network:
            self.assertEqual(len(self.picker.windows_images(candidate)), 8)
            self.assertLessEqual(network.call_count, 3)
        with mock.patch.object(model, 'MAX_IMAGES', 2):
            with self.assertRaisesRegex(model.PickerError, 'Too many'):
                self.picker.windows_images(candidate)

    def test_windows_identity_controls_relative_paths_and_ambiguous_sources_rejected(self):
        candidate = self.candidate()
        for value in (None, '', 'game.exe', r'C:game.exe', r'C:\game.dll', 'C:\\game.exe\nnew',
                      'C:\\game.exe\tloader', 'C:\\game.exe\x00', 'C:\\' + 'x' * 510 + '.exe'):
            with self.subTest(identity=value), self.assertRaises(model.PickerError):
                self.picker.mapping(candidate, windows_identity=value)
        image = pe_file(self.prefix / 'drive_c/game.exe')
        choice = self.picker.image_from_file(candidate, image)
        with self.assertRaises(model.PickerError):
            self.picker.mapping(candidate, image=choice, windows_identity=IDENTITY)

    def test_unix_path_control_characters_cannot_inject_map_rows(self):
        image = pe_file(self.prefix / 'drive_c/evil\nrow.exe')
        with self.assertRaises(model.PickerError):
            self.picker.image_from_file(self.candidate(), image)


@unittest.skipUnless(sys.platform == 'linux', 'Linux /proc socket ownership')
class LiveSockets(unittest.TestCase):
    def test_real_same_user_udp_socket_is_seen_and_closed_socket_cannot_be_reused(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
        except OSError as error:
            self.skipTest('loopback UDP unavailable: ' + str(error))
        self.addCleanup(sock.close)
        inode = int(os.readlink(f'/proc/self/fd/{sock.fileno()}')[8:-1])
        picker = model.ProcessPicker(DISCOVERY)
        candidate = next(item for item in picker.list_candidates() if item.pid == os.getpid())
        self.assertIn(inode, candidate.inodes)
        self.assertIn('udp', candidate.transports)
        # Restrict the proof to this one real fd, so unrelated framework sockets
        # do not keep this closed proof alive.
        candidate = replace(candidate, inodes=(inode,), socket_count=1)
        picker.revalidate(candidate)
        sock.close()
        with self.assertRaises(model.PickerError):
            picker.revalidate(candidate)

    def test_real_tcp_connect_and_accept_belong_to_the_running_process(self):
        try:
            server = socket.socket()
            self.addCleanup(server.close)
            server.bind(('127.0.0.1', 0))
            server.listen(1)
            server.settimeout(2)
            client = socket.socket()
            self.addCleanup(client.close)
            client.settimeout(2)
            client.connect(server.getsockname())
            accepted, _ = server.accept()
            self.addCleanup(accepted.close)
        except OSError as error:
            self.skipTest('loopback TCP unavailable: ' + str(error))
        client.sendall(b'picker')
        self.assertEqual(accepted.recv(6), b'picker')
        picker = model.ProcessPicker(DISCOVERY)
        candidate = next(item for item in picker.list_candidates() if item.pid == os.getpid())
        expected = {int(os.readlink(f'/proc/self/fd/{item.fileno()}')[8:-1])
                    for item in (server, client, accepted)}
        self.assertTrue(expected.issubset(candidate.inodes))
        self.assertIn('tcp', candidate.transports)
        picker.revalidate(candidate)


if __name__ == '__main__':
    unittest.main(verbosity=2)
