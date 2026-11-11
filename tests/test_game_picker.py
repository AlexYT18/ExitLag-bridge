#!/usr/bin/env python3
"""Headless mapping/controller/private-I/O/worker tests, without Wine or root."""
import importlib.util
import os
from pathlib import Path
import queue
import stat
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


picker = load('game_picker_units', ROOT / 'installers/linux/game_picker.py')
supervisor = load('picker_supervisor_units', ROOT / 'installers/linux/run_root.py')


class MappingControllerTests(unittest.TestCase):
    def test_existing_comments_blank_lines_and_legacy_rows_are_preserved(self):
        source = '# one\n\n/actual/game\tC:\\Games\\Game.exe\nwineprefix:/legacy\tC:\\Old.exe\n# last'
        model = picker.MappingController(source)
        rows = model.rows()
        self.assertEqual(model.text, source)
        self.assertEqual([row[2] for row in rows], ['Native', 'Needs review'])
        self.assertEqual(rows[0][1], 'Game.exe')
        model.remove([rows[0][0]])
        self.assertEqual(model.text, '# one\n\nwineprefix:/legacy\tC:\\Old.exe\n# last')
        self.assertEqual(model.original, source)

    def test_add_prefix_rule_needs_no_handwritten_tabs_or_newline(self):
        model = picker.MappingController('# saved comment')
        row = 'wineprefix:/actual/game prefix\tZ:\\Games\\Game.exe\t/actual/runtime'
        model.add(row)
        self.assertEqual(model.rows()[0][1:4], ('Game.exe', 'Wine / Proton', r'Z:\Games\Game.exe'))
        self.assertEqual(model.text, '# saved comment\n' + row + '\n')

    def test_duplicate_runtime_prefix_is_rejected_without_overwriting(self):
        row = 'wineprefix:/prefix\tC:\\First.exe\t/runtime\n'
        model = picker.MappingController(row)
        with self.assertRaisesRegex(ValueError, 'already configured'):
            model.add('wineprefix:/prefix\tC:\\Other.exe\t/runtime')
        self.assertEqual(model.text, row)
        model.add('wineprefix:/prefix\tC:\\Other.exe\t/other-runtime')
        self.assertEqual(len(model.rows()), 2)

    def test_duplicate_native_source_does_not_silently_replace_identity(self):
        model = picker.MappingController('/game\tC:\\First.exe\n')
        with self.assertRaises(ValueError): model.add('/game\tC:\\Other.exe')
        self.assertEqual(model.text, '/game\tC:\\First.exe\n')

    def test_injected_or_malformed_rows_do_not_modify_configuration(self):
        model = picker.MappingController('# intact\n')
        for value in ('', '/game', '/game\tC:\\One.exe\n/other\tC:\\Other.exe',
                      '/game\tC:\\One.exe\tunexpected', 'wineprefix:/prefix\tC:\\One.exe',
                      '/game\t', '/game\tC:\\One.exe\r', '/game\tC:\\One.exe\0'):
            with self.subTest(value=value), self.assertRaises(ValueError): model.add(value)
            self.assertEqual(model.text, '# intact\n')

    def test_advanced_edit_does_not_persist_or_discard_unrecognized_lines(self):
        model = picker.MappingController('# old\n')
        model.advanced('# new\nunknown old row\n')
        self.assertEqual(model.rows()[0][2], 'Needs review')
        self.assertEqual(model.original, '# old\n')
        with self.assertRaises(ValueError): model.advanced('x' * (picker.MAX_MAP + 1))
        self.assertEqual(model.text, '# new\nunknown old row\n')

    def test_replace_keeps_comments_order_and_original_snapshot(self):
        initial = '# comment\r\n/game\tC:\\First.exe\r\n\r\n/other\tC:\\Other.exe'
        model = picker.MappingController(initial)
        model.replace(1, '/game\tC:\\Changed.exe')
        self.assertEqual(model.text, '# comment\r\n/game\tC:\\Changed.exe\r\n\r\n/other\tC:\\Other.exe')
        self.assertEqual(model.original, initial)
        model.replace(3, '/other\tC:\\Last.exe')
        self.assertFalse(model.text.endswith('\n'))

    def test_replace_duplicate_or_injected_entry_keeps_entire_draft(self):
        initial = '/first\tC:\\First.exe\n/second\tC:\\Second.exe\n'
        model = picker.MappingController(initial)
        for row in ('/second\tC:\\Other.exe', '/first\tC:\\First.exe\n/injected\tC:\\Other.exe',
                    'wineprefix:/prefix\tC:\\Game.exe', '/first\t'):
            with self.subTest(row=row), self.assertRaises(ValueError):
                model.replace(0, row)
            self.assertEqual(model.text, initial)

    def test_replace_rejects_comment_blank_and_stale_selection(self):
        model = picker.MappingController('# keep\n\n/game\tC:\\Game.exe\n')
        for index in (-1, 0, 1, 3, True, '2'):
            with self.subTest(index=index), self.assertRaises(ValueError):
                model.replace(index, '/new\tC:\\New.exe')
        self.assertEqual(model.text, model.original)

    def test_replace_prefix_owner_and_capacity_are_checked(self):
        initial = 'wineprefix:/prefix\tC:\\Game.exe\t/runtime\n'
        model = picker.MappingController(initial)
        model.replace(0, 'wineprefix:/prefix\tC:\\Other.exe\t/other-runtime')
        changed = model.text
        with self.assertRaisesRegex(ValueError, 'too large'):
            model.replace(0, '/source\tC:\\' + ('x' * picker.MAX_MAP) + '.exe')
        self.assertEqual(model.text, changed)


class ProcessPresentationTests(unittest.TestCase):
    def candidate(self, name='Game.exe', executable='/private/user/game/runtime', prefix='/private/user/game/pfx'):
        return SimpleNamespace(name=name, pid=123, kind='proton', steam_appid='3527290',
                               executable=Path(executable), prefix=Path(prefix) if prefix else None)

    def test_details_show_actual_process_metadata_without_private_paths(self):
        details = picker.candidate_details(self.candidate())
        self.assertIn('PID 123', details)
        self.assertIn('3527290', details)
        self.assertIn('…/runtime', details)
        self.assertIn('…/pfx', details)
        self.assertNotIn('/private/user', details)
        self.assertEqual(picker.display_path(r'C:\Private User\Games\Game.exe'), '…/Game.exe')
        self.assertEqual(picker.display_path(None), '—')

    def test_wineserver_and_launcher_warn_without_inventing_identity(self):
        self.assertIn('wineserver', picker.candidate_warning(self.candidate('wineserver')))
        self.assertIn('launcher', picker.candidate_warning(self.candidate('Steam')))
        self.assertIn('launcher', picker.candidate_warning(self.candidate('GameLauncher.exe')))
        self.assertEqual(picker.candidate_warning(self.candidate(), 1), '')

    def test_ambiguous_and_missing_images_are_explicit(self):
        self.assertIn('несколько', picker.candidate_warning(self.candidate(), 2))
        self.assertIn('не найден', picker.candidate_warning(self.candidate(), 0))
        self.assertEqual(picker.candidate_warning(self.candidate(prefix=None), 0), '')


class ManualFallbackTests(unittest.TestCase):
    def test_cancelled_file_selection_does_not_request_identity(self):
        for prefix in (False, True):
            with self.subTest(prefix=prefix), mock.patch.object(picker.filedialog, 'askdirectory', return_value=''), mock.patch.object(picker.filedialog, 'askopenfilename', return_value=''), mock.patch.object(picker.simpledialog, 'askstring') as identity:
                self.assertIsNone(picker.manual_mapping(None, prefix))
                identity.assert_not_called()

    def test_offline_native_and_prefix_file_pickers_remain_available(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / 'game'; source.write_text('fixture')
            prefix = Path(work) / 'prefix'; prefix.mkdir()
            for is_prefix in (False, True):
                with self.subTest(prefix=is_prefix), mock.patch.object(picker.filedialog, 'askdirectory', return_value=str(prefix)), mock.patch.object(picker.filedialog, 'askopenfilename', return_value=str(source)), mock.patch.object(picker.simpledialog, 'askstring', return_value=r'C:\Game.exe'):
                    row = picker.manual_mapping(None, is_prefix)
                    parts = row.rstrip('\n').split('\t')
                    self.assertEqual(parts[0], ('wineprefix:' + str(prefix)) if is_prefix else str(source))
                    self.assertEqual(parts[1], r'C:\Game.exe')
                    self.assertEqual(len(parts), 3 if is_prefix else 2)
                    if is_prefix: self.assertEqual(parts[2], str(source))

    def test_manual_identity_cannot_inject_additional_rows(self):
        with tempfile.TemporaryDirectory() as work:
            source = Path(work) / 'game'; source.write_text('fixture')
            with mock.patch.object(picker.filedialog, 'askopenfilename', return_value=str(source)), mock.patch.object(picker.simpledialog, 'askstring', return_value='C:\\Game.exe\n/other\tC:\\Other.exe'):
                with self.assertRaises(ValueError): picker.manual_mapping(None)


class PrivateMapIOTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='exitlag-picker-unit-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / 'games.map'
        self.executable = self.directory / 'game'
        self.executable.write_text('#!/bin/sh\n')
        self.executable.chmod(0o700)
        self.text = str(self.executable) + '\tC:\\Games\\Game.exe\n'

    def existing(self, text=None):
        self.path.write_text(self.text if text is None else text)
        self.path.chmod(0o600)

    def test_absent_settings_load_empty_without_creating_a_file(self):
        self.assertEqual(picker.load_map(self.path), '')
        self.assertFalse(self.path.exists())

    def test_save_round_trip_uses_real_supervisor_parser_and_private_mode(self):
        observed = []
        def validate(path, uid):
            observed.append(path.read_text())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertFalse(self.path.exists(), 'validation must happen before replacement')
            return supervisor.read_map(path, uid)
        picker.save_map(self.path, self.text, validate, expected='')
        self.assertEqual(observed, [self.text])
        self.assertEqual(picker.load_map(self.path), self.text)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(list(self.directory.glob('.games-*.map')), [])

    def test_real_prefix_and_executable_with_spaces_validate(self):
        prefix = self.directory / 'game prefix'; prefix.mkdir()
        text = f'wineprefix:{prefix}\tZ:\\Actual Game.exe\t{self.executable}\n'
        picker.save_map(self.path, text, supervisor.read_map)
        self.assertEqual(supervisor.read_map(self.path, os.getuid()), text)

    def test_invalid_rule_preserves_previous_file_and_cleans_temporary(self):
        self.existing()
        for text in ('# no games\n', '/missing-game\tC:\\Game.exe\n', 'wineprefix:/missing\tC:\\Game.exe\n'):
            with self.subTest(text=text), self.assertRaises((ValueError, OSError)):
                picker.save_map(self.path, text, supervisor.read_map, expected=self.text)
            self.assertEqual(self.path.read_text(), self.text)
            self.assertEqual(list(self.directory.glob('.games-*.map')), [])

    def test_public_symlink_hardlink_and_fifo_are_refused(self):
        self.existing()
        self.path.chmod(0o644)
        with self.assertRaises(ValueError): picker.load_map(self.path)
        self.path.chmod(0o600)
        target = self.directory / 'other.map'; self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(OSError): picker.load_map(self.path)
        with self.assertRaises(ValueError): picker.save_map(self.path, self.text, supervisor.read_map)
        self.path.unlink(); os.link(target, self.path)
        with self.assertRaises(ValueError): picker.load_map(self.path)
        self.path.unlink(); target.unlink(); os.mkfifo(self.path, 0o600)
        with self.assertRaises(ValueError): picker.load_map(self.path)
        with self.assertRaises(ValueError): picker.save_map(self.path, self.text, supervisor.read_map)

    def test_wrong_owner_and_oversized_or_invalid_utf8_are_refused(self):
        self.existing()
        with self.assertRaises(ValueError): picker.load_map(self.path, os.getuid() + 1)
        with self.assertRaises(ValueError): picker.save_map(self.path, self.text, supervisor.read_map, uid=os.getuid() + 1)
        self.path.write_bytes(b'x' * (picker.MAX_MAP + 1))
        with self.assertRaises(ValueError): picker.load_map(self.path)
        self.path.write_bytes(b'\xff')
        with self.assertRaises(UnicodeError): picker.load_map(self.path)
        with self.assertRaises(ValueError): picker.save_map(self.path, 'x' * (picker.MAX_MAP + 1), supervisor.read_map)

    def test_writable_or_symlinked_parent_directory_is_refused(self):
        self.directory.chmod(0o770)
        with self.assertRaises(ValueError): picker.save_map(self.path, self.text, supervisor.read_map)
        self.directory.chmod(0o700)
        alias = self.directory / 'alias'; alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(OSError): picker.save_map(alias / 'games.map', self.text, supervisor.read_map)

    def test_external_edit_before_save_is_not_overwritten(self):
        self.existing('# externally changed\n' + self.text)
        with self.assertRaisesRegex(ValueError, 'changed elsewhere'):
            picker.save_map(self.path, self.text, supervisor.read_map, expected=self.text)
        self.assertTrue(self.path.read_text().startswith('# externally changed'))

    def test_external_edit_during_validation_is_not_overwritten(self):
        self.existing()
        changed = '# changed during validation\n' + self.text
        def validate(path, uid):
            supervisor.read_map(path, uid)
            self.path.write_text(changed)
        with self.assertRaisesRegex(ValueError, 'changed during validation'):
            picker.save_map(self.path, self.text, validate, expected=self.text)
        self.assertEqual(self.path.read_text(), changed)
        self.assertEqual(list(self.directory.glob('.games-*.map')), [])


class FilteringTests(unittest.TestCase):
    def candidate(self, name, pid, kind='proton', appid='12345'):
        return SimpleNamespace(name=name, pid=pid, kind=kind, steam_appid=appid,
                               executable=Path('/runtime/wine64-preloader'), transports=('udp',), socket_count=1)

    def test_games_with_shared_runtime_remain_separate_and_infrastructure_is_hidden(self):
        items = [self.candidate('wineserver', 1), self.candidate('Steam', 2),
                 self.candidate('Second.exe', 3), self.candidate('First.exe', 4)]
        self.assertEqual([x.name for x in picker.visible_candidates(items)], ['First.exe', 'Second.exe'])
        self.assertEqual(len(picker.visible_candidates(items, show_all=True)), 4)

    def test_case_insensitive_search_supports_name_pid_runtime_and_appid(self):
        items = [self.candidate('Game.exe', 4242)]
        for query in ('GAME', '4242', 'PROTON', '12345'):
            with self.subTest(query=query): self.assertEqual(picker.visible_candidates(items, query), items)
        self.assertEqual(picker.visible_candidates(items, 'missing'), [])

    def test_numeric_columns_sort_numbers_without_merging_processes(self):
        items = [self.candidate('Same.exe', 100, appid='100'),
                 self.candidate('Same.exe', 9, appid='9'),
                 self.candidate('Other.exe', 20, appid=None)]
        items[0].socket_count = 10
        items[1].socket_count = 2
        items[2].socket_count = 3
        self.assertEqual([x.pid for x in picker.visible_candidates(items, sort_by='pid')], [9, 20, 100])
        self.assertEqual([x.pid for x in picker.visible_candidates(items, sort_by='pid', descending=True)], [100, 20, 9])
        self.assertEqual([x.pid for x in picker.visible_candidates(items, sort_by='sockets')], [9, 20, 100])
        self.assertEqual([x.pid for x in picker.visible_candidates(items, sort_by='appid')], [9, 100, 20])
        self.assertEqual([x.pid for x in picker.visible_candidates(items, 'same', sort_by='pid')], [9, 100])

    def test_sorting_keeps_hidden_infrastructure_hidden(self):
        items = [self.candidate('Steam', 2), self.candidate('Game.exe', 9)]
        for column in ('name', 'pid', 'runtime', 'transport', 'sockets', 'appid'):
            with self.subTest(column=column):
                self.assertEqual(picker.visible_candidates(items, sort_by=column), items[1:])


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.tasks = picker.TaskQueue()
        self.addCleanup(self.tasks.close)

    def pump(self, until, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.tasks.poll()
            if until(): return
            time.sleep(.001)
        self.fail('worker did not finish')

    def test_operations_run_off_thread_callbacks_only_run_when_owner_polls(self):
        owner = threading.get_ident(); operations = []; callbacks = []; finished = threading.Event()
        def work():
            operations.append(threading.get_ident()); finished.set(); return 'result'
        self.tasks.submit('scan', work, lambda value, error: callbacks.append((value, error, threading.get_ident())))
        self.assertTrue(finished.wait(2))
        self.assertEqual(callbacks, [])
        self.pump(lambda: bool(callbacks))
        self.assertNotEqual(operations, [owner])
        self.assertEqual(callbacks, [('result', None, owner)])

    def test_worker_error_is_delivered_without_mutating_ui_state(self):
        received = []
        def work(): raise ValueError('process exited')
        self.tasks.submit('mapping', work, lambda value, error: received.append((value, str(error))))
        self.pump(lambda: bool(received))
        self.assertEqual(received, [(None, 'process exited')])

    def test_replaced_selection_discards_older_scan_result(self):
        release = threading.Event(); self.addCleanup(release.set); seen = []
        self.tasks.submit('images', lambda: release.wait(2) and 'old', lambda value, error: seen.append(value))
        self.tasks.submit('images', lambda: 'new', lambda value, error: seen.append(value))
        self.pump(lambda: bool(seen)); self.assertEqual(seen, ['new'])
        release.set(); self.pump(lambda: not self.tasks.active)
        self.assertEqual(seen, ['new'])

    def test_cancel_and_close_prevent_late_callbacks(self):
        release = threading.Event(); self.addCleanup(release.set); seen = []
        self.tasks.submit('mapping', lambda: release.wait(2), lambda value, error: seen.append(value))
        self.tasks.cancel('mapping'); self.tasks.close(); release.set()
        self.pump(lambda: not self.tasks.active)
        self.assertEqual(seen, [])
        with self.assertRaises(RuntimeError): self.tasks.submit('scan', lambda: None, lambda *_: None)

    def test_worker_capacity_is_bounded(self):
        release = threading.Event(); self.addCleanup(release.set)
        for number in range(4):
            self.tasks.submit(str(number), lambda: release.wait(2), lambda *_: None)
        with self.assertRaisesRegex(ValueError, 'still running'):
            self.tasks.submit('excess', lambda: None, lambda *_: None)
        release.set(); self.pump(lambda: not self.tasks.active)

    def test_non_owner_cannot_poll_or_run_callbacks(self):
        result = queue.Queue()
        def outside():
            try: self.tasks.poll()
            except Exception as error: result.put(error)
        worker = threading.Thread(target=outside); worker.start(); worker.join(2)
        self.assertIsInstance(result.get_nowait(), RuntimeError)


if __name__ == '__main__':
    unittest.main(verbosity=2)
