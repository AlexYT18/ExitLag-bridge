#!/usr/bin/env python3
"""Exercise actual Tk widgets against synthetic process data in a private Xvfb.

No Wine, ExitLag account, game, network configuration or root is used.
"""
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from dataclasses import replace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'installers'))
sys.path.insert(0, str(ROOT / 'installers/linux'))

from bridge_setup.process_picker import Candidate, ImageCandidate, PickerError
from game_picker import MappingEditor
import game_picker
from run_root import read_map


class SyntheticPicker:
    def __init__(self, directory):
        self.owner = directory / 'approved runtime'
        self.owner.write_text('#!/bin/sh\n')
        self.owner.chmod(0o700)
        self.prefix = directory / 'game prefix'
        self.prefix.mkdir()
        self.candidate = Candidate(4242, os.getuid(), 101, 'Synthetic Game.exe',
                                   'proton', self.owner, self.prefix,
                                   ('tcp', 'udp'), 2, (111, 222), '12345')
        self.images = [self.image(directory / 'Synthetic Game.exe', r'C:\Games\Synthetic Game.exe')]
        self.stale = False
        self.release_scan = None
        self.scan_started = threading.Event()
        self.worker_threads = []
        self.release_file = None
        self.file_started = threading.Event()
        self.file_finished = threading.Event()

    @staticmethod
    def image(path, windows_path):
        path.write_bytes(b'fixture; validated PE parsing is covered by model tests')
        info = path.stat()
        return ImageCandidate(path, windows_path, info.st_dev, info.st_ino,
                              info.st_size, info.st_mtime_ns, info.st_ctime_ns, True)

    def list_candidates(self):
        self.worker_threads.append(threading.get_ident())
        self.scan_started.set()
        if self.release_scan is not None and not self.release_scan.wait(5):
            raise PickerError('Synthetic scan timed out')
        return [self.candidate]

    def revalidate(self, candidate):
        if self.stale or candidate != self.candidate:
            raise PickerError('Process changed; refresh and select it again')

    def windows_images(self, candidate):
        self.revalidate(candidate)
        return list(self.images)

    def image_from_file(self, candidate, path):
        self.revalidate(candidate)
        self.file_started.set()
        if self.release_file is not None and not self.release_file.wait(5):
            raise PickerError('Synthetic file inspection timed out')
        self.file_finished.set()
        return self.image(Path(path), r'C:\Games\Other.exe')

    def mapping(self, candidate, windows_identity=None, image=None):
        self.worker_threads.append(threading.get_ident())
        self.revalidate(candidate)
        if image is None and not windows_identity:
            raise PickerError('Choose an actual Windows executable')
        identity = image.windows_path if image is not None else windows_identity
        return (f'wineprefix:{self.prefix}\t{identity}\t{self.owner}'
                if candidate.prefix else f'{self.owner}\t{identity}')


class RealTkPicker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import tkinter as tk
        read_fd, write_fd = os.pipe()
        cls.server = subprocess.Popen(
            ['Xvfb', '-displayfd', str(write_fd), '-screen', '0', '1280x900x24', '-nolisten', 'tcp'],
            pass_fds=(write_fd,), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.close(write_fd)
        try:
            if not select.select([read_fd], [], [], 10)[0]:
                raise RuntimeError('Xvfb readiness timed out')
            number = os.read(read_fd, 64).decode().strip()
            if not number.isdigit():
                raise RuntimeError('Xvfb did not return a display number')
            cls.display = ':' + number
            cls.root = tk.Tk(screenName=cls.display)
            cls.root.title('Synthetic GUI test')
            cls.root.geometry('1x1+1250+850')
        except Exception:
            cls.server.terminate()
            cls.server.wait(timeout=5)
            raise
        finally:
            os.close(read_fd)

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()
        cls.server.terminate()
        try:
            cls.server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.server.kill()
            cls.server.wait(timeout=5)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='exitlag-picker-tk-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.path = self.directory / 'games.map'
        self.picker = SyntheticPicker(self.directory)
        self.editor = MappingEditor(self.root, self.path, ROOT, picker=self.picker,
                                    validator=read_map)
        self.addCleanup(self.editor.close)

    def pump(self, predicate, timeout=5):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.root.update()
            if predicate():
                return
            time.sleep(.01)
        self.fail('Tk asynchronous action did not complete before its deadline')

    def select_running_game(self):
        dialog = self.editor.open_running()
        self.pump(lambda: bool(dialog.process_tree.get_children()))
        self.assertTrue(dialog.window.winfo_viewable(), 'the real picker must be visible')
        entry = dialog.process_tree.get_children()[0]
        dialog.process_tree.selection_set(entry)
        dialog.process_tree.event_generate('<<TreeviewSelect>>')
        self.pump(lambda: dialog.selected is not None and bool(dialog.images))
        return dialog

    def test_select_game_and_save_private_valid_map(self):
        dialog = self.select_running_game()
        self.pump(lambda: not dialog.add_button.instate(['disabled']))
        self.assertFalse(self.path.exists(), 'process selection must not silently persist a rule')
        preview = os.environ.get('EXL_GUI_PREVIEW')
        if preview:
            from PIL import ImageGrab
            self.root.update()
            ImageGrab.grab(xdisplay=self.display).save(preview)
        dialog.add()
        self.pump(lambda: bool(self.editor.tree.get_children()))
        self.editor.save()
        self.pump(self.path.exists)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(read_map(self.path, os.getuid()).strip(),
                         self.picker.mapping(self.picker.candidate, image=self.picker.images[0]))
        self.assertTrue(self.picker.worker_threads)
        # The last explicit mapping assertion is in the main test thread.
        self.assertTrue(all(worker != threading.get_ident()
                            for worker in self.picker.worker_threads[:-1]))

    def test_stale_process_keeps_rule_list_unchanged(self):
        dialog = self.select_running_game()
        self.pump(lambda: not dialog.add_button.instate(['disabled']))
        self.picker.stale = True
        dialog.add()
        self.pump(lambda: 'changed' in dialog.status.get().lower())
        self.assertEqual(self.editor.tree.get_children(), ())
        self.assertFalse(self.path.exists())

    def test_two_images_require_explicit_selection(self):
        second = self.picker.image(self.directory / 'Second.exe', r'C:\Games\Second.exe')
        self.picker.images.append(second)
        dialog = self.select_running_game()
        self.assertEqual(dialog.image_combo.current(), -1)
        self.assertTrue(dialog.add_button.instate(['disabled']))
        dialog.image_combo.current(1)
        dialog.image_combo.event_generate('<<ComboboxSelected>>')
        self.pump(lambda: not dialog.add_button.instate(['disabled']))
        dialog.add()
        self.pump(lambda: bool(self.editor.tree.get_children()))
        self.assertIn(second.windows_path, self.editor.controller.text)

    def test_native_game_requires_confirmed_identity(self):
        self.picker.candidate = replace(self.picker.candidate, kind='native', prefix=None)
        self.picker.images.clear()
        dialog = self.editor.open_running()
        self.pump(lambda: bool(dialog.process_tree.get_children()))
        dialog.process_tree.selection_set(dialog.process_tree.get_children()[0])
        dialog.process_tree.event_generate('<<TreeviewSelect>>')
        self.pump(lambda: 'No mapped game image' in dialog.status.get())
        self.assertTrue(dialog.add_button.instate(['disabled']))
        identity = r'C:\Confirmed\NativeEquivalent.exe'
        with mock.patch.object(game_picker.simpledialog, 'askstring', return_value=identity):
            dialog.advanced_identity()
        dialog.add()
        self.pump(lambda: bool(self.editor.tree.get_children()))
        self.assertEqual(self.editor.controller.text.strip(), f'{self.picker.owner}\t{identity}')

    def test_combo_selection_wins_over_older_file_inspection(self):
        dialog = self.select_running_game()
        self.picker.release_file = threading.Event()
        self.addCleanup(self.picker.release_file.set)
        other = self.directory / 'Other.exe'
        with mock.patch.object(game_picker.filedialog, 'askopenfilename', return_value=str(other)):
            dialog.choose_file()
        self.pump(self.picker.file_started.is_set)
        dialog.image_combo.current(0)
        dialog.image_combo.event_generate('<<ComboboxSelected>>')
        self.pump(lambda: not dialog.add_button.instate(['disabled']))
        self.picker.release_file.set()
        self.pump(lambda: self.picker.file_finished.is_set() and not dialog.tasks.active)
        self.assertEqual(dialog.images, self.picker.images)
        dialog.add()
        self.pump(lambda: bool(self.editor.tree.get_children()))
        self.assertIn(self.picker.images[0].windows_path, self.editor.controller.text)
        self.assertNotIn(r'C:\Games\Other.exe', self.editor.controller.text)

    def test_slow_scan_keeps_tk_responsive_and_close_ignores_result(self):
        self.picker.release_scan = threading.Event()
        self.addCleanup(self.picker.release_scan.set)
        dialog = self.editor.open_running()
        self.pump(self.picker.scan_started.is_set)
        ticks = []
        self.root.after(0, lambda: ticks.append(True))
        self.pump(lambda: bool(ticks))
        dialog.close()
        self.picker.release_scan.set()
        for _ in range(10):
            self.root.update()
            time.sleep(.01)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.editor.tree.get_children(), ())

    def test_saturated_checks_leave_refresh_available_for_retry(self):
        dialog = self.select_running_game()
        release = threading.Event()
        self.addCleanup(release.set)
        for number in range(4):
            dialog.tasks.submit(f'busy-{number}', lambda: release.wait(3), lambda *_: None)
        dialog.refresh()
        self.assertFalse(dialog.refresh_button.instate(['disabled']))
        self.assertIn('still running', dialog.status.get())
        release.set()
        self.pump(lambda: not dialog.tasks.active)
        dialog.refresh()
        self.pump(lambda: not dialog.refresh_button.instate(['disabled']))
        self.assertEqual(len(dialog.process_tree.get_children()), 1)


if __name__ == '__main__':
    if not shutil.which('Xvfb'):
        print('SKIP: Xvfb is required for actual Tk integration')
        raise SystemExit(77)
    unittest.main(verbosity=2)
