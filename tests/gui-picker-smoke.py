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
import app as desktop_app
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
            from tkinter import font
            self.assertIn('DejaVu Sans', font.families(self.root), 'Preview needs Unicode fonts; use the distribution Python/Tk')
            from PIL import ImageGrab
            self.root.update()
            x, y = dialog.window.winfo_rootx(), dialog.window.winfo_rooty()
            bounds = (x, y, x + dialog.window.winfo_width(), y + dialog.window.winfo_height())
            ImageGrab.grab(xdisplay=self.display, bbox=bounds).save(preview)
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

    def test_sort_and_search_preserve_image_without_saving_and_clear_hidden_selection(self):
        dialog = self.select_running_game()
        self.pump(lambda: not dialog.add_button.instate(['disabled']))
        selected = dialog.process_tree.selection()
        image = dialog.image_combo.get()
        second = replace(self.picker.candidate, pid=9, start_time=102, name='Other.exe', steam_appid='9')
        dialog.candidates.append(second)
        dialog.window.tk.call(dialog.process_tree.heading('pid', 'command')); self.root.update()
        self.assertEqual(dialog.process_tree.get_children()[0], '9:102')
        self.assertEqual(dialog.process_tree.selection(), selected)
        self.assertEqual(dialog.image_combo.get(), image)
        self.assertFalse(dialog.add_button.instate(['disabled']))
        dialog.window.tk.call(dialog.process_tree.heading('pid', 'command')); self.root.update()
        self.assertEqual(dialog.process_tree.get_children()[0], selected[0])
        dialog.query.set('Synthetic'); self.root.update()
        self.assertEqual(dialog.process_tree.selection(), selected)
        self.assertEqual(dialog.image_combo.get(), image)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.editor.controller.text, '')
        dialog.query.set('missing'); self.root.update()
        self.assertIsNone(dialog.selected)
        self.assertEqual(dialog.image_combo.get(), '')
        self.assertEqual(dialog.details.get(), '')
        self.assertTrue(dialog.add_button.instate(['disabled']))
        self.assertTrue(dialog.browse_button.instate(['disabled']))
        dialog.clear_button.invoke(); self.root.update()
        self.assertEqual(dialog.query.get(), '')
        self.assertEqual(len(dialog.process_tree.get_children()), 2)
        self.assertIsNone(dialog.selected)
        self.assertIn('Experimental UDP', dialog.transport_note.cget('text'))
        self.assertIn('do not verify routing', dialog.transport_note.cget('text'))

    def test_keyboard_search_navigation_and_refresh_do_not_add_a_rule(self):
        dialog = self.editor.open_running()
        self.pump(lambda: bool(dialog.process_tree.get_children()))
        dialog.window.focus_force(); dialog.focus_search(); self.root.update()
        dialog.query.set('Synthetic')
        dialog.search_entry.event_generate('<Down>')
        self.pump(lambda: dialog.selected is not None and bool(dialog.images))
        self.assertEqual(dialog.process_tree.focus(), dialog.process_tree.selection()[0])
        dialog.process_tree.event_generate('<Control-f>'); self.root.update()
        self.assertEqual(dialog.window.focus_get(), dialog.search_entry)
        self.assertTrue(dialog.search_entry.selection_present())
        dialog.search_entry.event_generate('<F5>')
        self.pump(lambda: not dialog.refresh_button.instate(['disabled']))
        self.assertIsNone(dialog.selected)
        self.assertEqual(dialog.process_tree.selection(), ())
        self.assertTrue(dialog.add_button.instate(['disabled']))
        self.assertFalse(self.path.exists())
        self.assertEqual(self.editor.controller.text, '')

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
        self.assertIn('несколько', dialog.selection_warning.get())
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

    @staticmethod
    def widget_texts(widget):
        result = []
        if widget.winfo_class() in ('TLabel', 'TButton', 'Button', 'Label'):
            result.append(str(widget.cget('text')))
        for child in widget.winfo_children():
            result.extend(RealTkPicker.widget_texts(child))
        return result

    def button(self, parent, text):
        def find(widget):
            if widget.winfo_class() in ('TButton', 'Button') and widget.cget('text') == text:
                return widget
            for child in widget.winfo_children():
                result = find(child)
                if result is not None:
                    return result
        result = find(parent)
        self.assertIsNotNone(result, f'Actual button is missing: {text}')
        return result

    def dashboard(self):
        import tkinter as tk
        import queue
        self.editor.close()
        desktop = desktop_app.Desktop.__new__(desktop_app.Desktop)
        desktop.window = tk.Toplevel(self.root)
        desktop.window.geometry('1180x760+20+20')
        desktop.state = self.directory
        desktop.busy = False; desktop.helper = desktop.client = None
        desktop.started = None; desktop.last_check = 0; desktop.checking = False
        desktop.lock = None; desktop.events = queue.Queue()
        desktop.message = tk.StringVar(master=desktop.window, value='Тест интерфейса: клиент и маршрутизация не запущены.')
        desktop.udp_enabled = tk.BooleanVar(master=desktop.window, value=False)
        desktop.selected_game = tk.StringVar(master=desktop.window, value='Выберите игру')
        desktop.selected_details = tk.StringVar(master=desktop.window)
        desktop.session_status = tk.StringVar(master=desktop.window, value='Остановлено')
        desktop.relay_status = tk.StringVar(master=desktop.window, value='Маршрут не подтверждён')
        desktop.transport_status = tk.StringVar(master=desktop.window, value='TCP')
        desktop.mapping_rows = {}
        desktop._build_ui()
        def cleanup():
            desktop.tasks.close()
            # Tk does not cancel timer entries when destroying registered Tcl
            # commands. Cancel only callbacks registered on this test window.
            commands = set(desktop.window._tclCommands or ())
            for timer in desktop.window.tk.call('after', 'info'):
                detail = desktop.window.tk.call('after', 'info', timer)
                if detail and str(detail[0]) in commands:
                    desktop.window.after_cancel(timer)
            if desktop.window.winfo_exists():
                desktop.window.destroy()
        self.addCleanup(cleanup)
        desktop.refresh_game_list()
        # Exercise real main-thread task delivery without starting supervisor
        # lifecycle polling against the deliberately synthetic Popen handles.
        def poll_tasks():
            if not desktop.tasks.closed:
                desktop.tasks.poll()
                desktop.window.after(20, poll_tasks)
        desktop.window.after(20, poll_tasks)
        self.root.update()
        return desktop

    def test_dashboard_uses_selected_game_and_explicit_udp_without_verified_relay(self):
        desktop = self.dashboard()
        self.assertTrue(desktop.pages['home'].winfo_viewable())
        self.assertTrue(desktop.udp_toggle.instate(['disabled']))
        self.assertFalse(desktop.udp_enabled.get())
        self.assertEqual(desktop.relay_status.get(), 'Маршрут не подтверждён')
        self.path.write_text(self.picker.mapping(self.picker.candidate, image=self.picker.images[0]) + '\n')
        self.path.chmod(0o600)
        desktop._setup_ready = True
        desktop.candidates = [self.picker.candidate]
        desktop._scan_time = time.monotonic()
        desktop.refresh_game_list(); self.root.update()
        self.assertEqual(desktop.selected_game.get(), 'Synthetic Game.exe')
        self.assertIn('4242', desktop.selected_details.get())
        self.assertIn('…/approved runtime', desktop.selected_details.get())
        self.assertNotIn(str(self.directory), desktop.selected_details.get())
        self.assertFalse(desktop.udp_toggle.instate(['disabled']))
        self.assertNotIn('--udp', desktop._helper_command())
        desktop.udp_enabled.set(True); desktop._sync_controls()
        self.assertIn('--udp', desktop._helper_command())
        self.assertEqual(desktop.session_status.get(), 'Остановлено')
        self.assertEqual(desktop.relay_status.get(), 'Маршрут не подтверждён')
        desktop.saved_query.set('12345'); self.root.update()
        self.assertEqual(len(desktop.game_list.get_children()), 1)
        desktop.saved_query.set('missing'); self.root.update()
        self.assertEqual(desktop.game_list.get_children(), ())
        desktop.saved_query.set(''); self.root.update()
        preview = os.environ.get('EXL_DASHBOARD_PREVIEW')
        if preview:
            from tkinter import font
            self.assertIn('DejaVu Sans', font.families(self.root), 'Preview needs Unicode fonts; use the distribution Python/Tk')
            from PIL import ImageGrab
            self.root.update()
            x, y = desktop.window.winfo_rootx(), desktop.window.winfo_rooty()
            bounds = (x, y, x + desktop.window.winfo_width(), y + desktop.window.winfo_height())
            ImageGrab.grab(xdisplay=self.display, bbox=bounds).save(preview)
        desktop.helper = mock.Mock(); desktop._sync_controls()
        self.assertEqual(desktop.primary_button.cget('text'), 'Остановить')
        self.assertTrue(desktop.udp_toggle.instate(['disabled']))
        self.assertEqual(desktop.session_status.get(), 'Запуск')
        desktop.client = mock.Mock(); desktop._backend_ready = True; desktop._sync_controls()
        self.assertEqual(desktop.session_status.get(), 'Клиент запущен')
        self.assertEqual(desktop.client_status.get(), 'Запущен')
        self.assertEqual(desktop.relay_status.get(), 'Маршрут не подтверждён')
        desktop._error('Private failure /home/private/user/runtime')
        self.assertEqual(desktop.session_status.get(), 'Ошибка')
        self.assertNotIn('/home/private', desktop.message.get())

    def test_all_navigation_pages_keep_primary_connection_control_and_honest_metrics(self):
        desktop = self.dashboard()
        desktop.window.geometry('1040x680+20+20')
        self.root.update()
        self.assertEqual(set(desktop.nav_buttons), {'home', 'games', 'statistics', 'setup', 'diagnostics'})
        self.assertEqual(desktop.primary_button, desktop.launch_button)
        with mock.patch.object(desktop, 'scan_processes') as scan:
            for name, button in desktop.nav_buttons.items():
                button.invoke(); self.root.update()
                self.assertTrue(desktop.pages[name].winfo_viewable(), name)
                self.assertTrue(desktop.primary_button.winfo_viewable(), name)
                self.assertGreaterEqual(desktop.primary_button.winfo_rootx(), desktop.window.winfo_rootx())
                self.assertLessEqual(desktop.primary_button.winfo_rootx() + desktop.primary_button.winfo_width(),
                                     desktop.window.winfo_rootx() + desktop.window.winfo_width())
                self.assertLessEqual(desktop.primary_button.winfo_rooty() + desktop.primary_button.winfo_height(),
                                     desktop.window.winfo_rooty() + desktop.window.winfo_height())
                for other, page in desktop.pages.items():
                    if other != name:
                        self.assertFalse(page.winfo_viewable(), other)
            scan.assert_called_once_with()
        labels = self.widget_texts(desktop.pages['statistics'])
        self.assertEqual(labels.count('Не измеряется'), 4)
        self.assertFalse(any('0 ms' in label or '0%' in label or '0 MB' in label for label in labels))
        self.assertEqual(desktop.relay_status.get(), 'Маршрут не подтверждён')
        with mock.patch.object(desktop, 'launch') as launch:
            desktop.primary_button.invoke()
            launch.assert_called_once_with()
        desktop.helper = mock.Mock(); desktop._sync_controls()
        with mock.patch.object(desktop, 'stop_routing') as stop:
            desktop.primary_button.invoke()
            stop.assert_called_once_with()

    def test_games_discovery_search_and_process_card_use_actual_async_result(self):
        desktop = self.dashboard()
        release = threading.Event()
        self.addCleanup(release.set)
        self.picker.release_scan = release
        with mock.patch('bridge_setup.process_picker.ProcessPicker', return_value=self.picker) as provider:
            desktop.show_page('games')
            self.pump(self.picker.scan_started.is_set)
            self.assertTrue(desktop.scan_button.instate(['disabled']))
            ticks = []
            desktop.window.after(0, lambda: ticks.append(True))
            self.pump(lambda: bool(ticks))
            self.assertEqual(desktop.process_tree.get_children(), ())
            release.set()
            self.pump(lambda: not desktop.scan_button.instate(['disabled']))
        provider.assert_called_once_with(ROOT / 'tools/discover-game-processes.py')
        self.assertEqual(desktop.process_tree.get_children(), ('4242:101',))
        self.assertIn('12345', desktop.process_tree.item('4242:101', 'values'))
        desktop.process_query.set('12345'); self.root.update()
        self.assertEqual(desktop.process_tree.get_children(), ('4242:101',))
        desktop.process_tree.selection_set('4242:101')
        desktop.process_tree.event_generate('<<TreeviewSelect>>')
        self.pump(lambda: '4242' in desktop.process_details.get())
        self.assertNotIn(str(self.directory), desktop.process_details.get())
        self.assertFalse(desktop.add_process_button.instate(['disabled']))
        self.assertFalse(self.path.exists(), 'discovery must not silently authorize a process')
        desktop.process_query.set('missing'); self.root.update()
        self.assertEqual(desktop.process_tree.get_children(), ())
        self.assertTrue(desktop.add_process_button.instate(['disabled']))
        self.assertEqual(desktop.process_warning.get(), '')
        self.assertEqual(desktop.relay_status.get(), 'Маршрут не подтверждён')
        self.assertTrue(self.picker.worker_threads)
        self.assertTrue(all(t != threading.get_ident() for t in self.picker.worker_threads))

    def test_diagnostics_render_and_clipboard_hide_secrets_and_private_paths(self):
        desktop = self.dashboard()
        desktop.show_page('diagnostics')
        private = ('token=private-session-secret\npassword=secret-password\n'
                   'exe=/home/private user/game/secret.exe\n'
                   r'prefix=C:\Users\Private Person\Game' + '\n'
                   'status: synthetic local error')
        desktop.set_diagnostics_text(private)
        self.assertEqual(desktop.diagnostics_text.cget('state'), 'disabled')
        shown = desktop.diagnostics_text.get('1.0', 'end-1c')
        for secret in ('private-session-secret', 'secret-password', '/home/private', 'Private Person'):
            self.assertNotIn(secret, shown)
        self.assertIn('synthetic local error', shown)
        desktop.copy_diagnostics(); self.root.update()
        self.assertEqual(desktop.window.clipboard_get(), shown)
        with mock.patch.object(desktop_app, 'diagnostics_snapshot', return_value='token=never-shown\nstatus: ready'):
            desktop.refresh_diagnostics()
            self.pump(lambda: not desktop.tasks.active)
        self.assertIn('status: ready', desktop.diagnostics_text.get('1.0', 'end-1c'))
        self.assertNotIn('never-shown', desktop.diagnostics_text.get('1.0', 'end-1c'))

    def test_slow_stop_keeps_tk_alive_and_releases_session_after_worker_finishes(self):
        desktop = self.dashboard()
        release = threading.Event(); entered = threading.Event()
        self.addCleanup(release.set)
        desktop.helper = mock.Mock()
        desktop.client = mock.Mock()
        desktop.started = time.time()
        lease = self.directory / 'desktop.lease'; lease.write_text('run\n')
        def slow_stop(_state):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Synthetic stop fixture was not released')
            return ''
        with mock.patch.object(desktop_app, 'stop_client', side_effect=slow_stop):
            desktop.request_stop()
            self.assertTrue(entered.wait(1))
            self.assertFalse(lease.exists())
            self.assertTrue(desktop._stopping)
            self.assertTrue(desktop.primary_button.instate(['disabled']))
            ticks = []
            self.root.after(0, lambda: ticks.append(True))
            self.pump(lambda: bool(ticks))
            self.assertIsNotNone(desktop.client)
            release.set()
            desktop.poll()
            self.pump(lambda: not desktop._stopping)
        self.assertIsNone(desktop.client)
        self.assertIsNone(desktop.helper)
        self.assertEqual(desktop.session_status.get(), 'Остановлено')
        self.assertEqual(desktop.primary_button.cget('text'), 'Подключить')
        self.assertTrue(desktop.window.winfo_viewable())

    def test_edit_game_apply_cancel_and_save_preserve_private_validation(self):
        original = self.picker.mapping(self.picker.candidate, image=self.picker.images[0])
        self.editor.add_row(original)
        self.editor.tree.selection_set('0')
        dialog = self.editor.edit_selected(); self.root.update()
        self.assertIsNotNone(dialog)
        self.assertNotIn(str(self.directory), '\n'.join(self.widget_texts(dialog)))
        identity = r'C:\Games\Changed.exe'
        with mock.patch.object(game_picker.simpledialog, 'askstring', return_value=identity):
            self.button(dialog, 'Windows identity…').invoke()
        self.button(dialog, 'Применить').invoke(); self.root.update()
        self.assertIn(identity, self.editor.controller.text)
        self.assertFalse(self.path.exists(), 'edit must remain a draft until Save')
        draft = self.editor.controller.text
        dialog = self.editor.edit_selected(); self.root.update()
        with mock.patch.object(game_picker.simpledialog, 'askstring', return_value=r'C:\Games\Cancelled.exe'):
            self.button(dialog, 'Windows identity…').invoke()
        self.button(dialog, 'Отмена').invoke(); self.root.update()
        self.assertEqual(self.editor.controller.text, draft)
        self.editor.save(); self.pump(self.path.exists)
        self.assertIn(identity, read_map(self.path, os.getuid()))
        self.assertNotIn('Cancelled.exe', self.path.read_text())
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_running_picker_reports_launcher_and_wineserver_with_masked_details(self):
        for name in ('wineserver', 'GameLauncher.exe'):
            self.picker.candidate = replace(self.picker.candidate, name=name)
            dialog = self.editor.open_running()
            self.pump(lambda: not dialog.refresh_button.instate(['disabled']))
            dialog.show_all.set(True); dialog.render()
            self.assertEqual(len(dialog.process_tree.get_children()), 1)
            dialog.process_tree.selection_set(dialog.process_tree.get_children()[0])
            dialog.process_tree.event_generate('<<TreeviewSelect>>')
            self.pump(lambda: dialog.selected is not None and bool(dialog.images))
            self.assertIn('wineserver' if name == 'wineserver' else 'launcher', dialog.selection_warning.get())
            self.assertIn('4242', dialog.details.get())
            self.assertNotIn(str(self.directory), dialog.details.get())
            self.root.update()
            self.assertTrue(dialog.add_button.winfo_viewable())
            self.assertTrue(dialog.status_label.winfo_viewable())
            self.assertTrue(dialog.image_combo.winfo_viewable())
            self.assertLessEqual(dialog.status_label.winfo_rooty() + dialog.status_label.winfo_height(),
                                 dialog.window.winfo_rooty() + dialog.window.winfo_height())
            dialog.close()


if __name__ == '__main__':
    if not shutil.which('Xvfb'):
        print('SKIP: Xvfb is required for actual Tk integration')
        raise SystemExit(77)
    unittest.main(verbosity=2)
