#!/usr/bin/env python3
"""Headless desktop lifecycle tests; no Tk window, Wine, account or root."""
import importlib.util
import os
from pathlib import Path
import queue
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('linux_desktop_app', ROOT / 'installers/linux/app.py')
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class DesktopLifecycle(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.desktop = app.Desktop.__new__(app.Desktop)
        self.desktop.state = Path(temporary.name)
        self.desktop.events = queue.Queue()
        self.desktop.checking = True
        self.desktop.client = self.desktop.helper = None
        self.desktop.message = mock.Mock()
        self.desktop.lock = None
        self.desktop.busy = False
        self.desktop._stopping = self.desktop._closing = self.desktop._backend_ready = False
        self.desktop._stop_failed = False
        self.desktop._session_generation = 1
        self.desktop._last_error = ''
        self.desktop.started = app.time.time()
        self.desktop.last_check = app.time.time()
        self.desktop.window = mock.Mock()
        self.desktop.tasks = mock.Mock(closed=False)
        self.desktop._sync_controls = mock.Mock()

    def events(self):
        values = []
        while not self.desktop.events.empty(): values.append(self.desktop.events.get_nowait())
        return values

    def complete_worker(self):
        event = self.desktop.events.get(timeout=3)
        self.assertEqual(event[0], 'stop_complete')
        self.desktop.events.put(event)
        self.desktop.poll()

    def test_live_client_is_preserved_for_windows_console_encodings(self):
        listing = '\r\nExitLag.exe             123 Console       1 100,000 K\r\n'
        for encoding in ('utf-8', 'utf-16', 'utf-16le', 'utf-16be'):
            data = listing.encode(encoding)
            if encoding == 'utf-16be': data = b'\xfe\xff' + data
            with self.subTest(encoding=encoding), mock.patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, data)):
                self.desktop.checking = True
                self.desktop.check_client()
                self.assertTrue(self.desktop.checking, 'worker must not mutate UI state')
                values = self.events()
                self.assertEqual([value[0] for value in values], ['client_check_done'])
                for value in values: self.desktop.events.put(value)
                self.desktop.poll()
                self.assertFalse(self.desktop.checking)

    def test_successful_query_of_absent_client_requests_stop_on_ui_thread(self):
        absent = 'INFO: No tasks are running which match the specified criteria.\r\n'
        with mock.patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, absent.encode('utf-16'))):
            self.desktop.check_client()
        values = self.events()
        self.assertEqual([value[0] for value in values], ['client_closed', 'client_check_done'])
        self.assertTrue(self.desktop.checking)
        for value in values: self.desktop.events.put(value)
        with mock.patch.object(self.desktop, 'request_stop') as stop:
            self.desktop.poll()
        stop.assert_called_once_with()

    def test_failed_or_timed_out_query_does_not_claim_client_exit(self):
        cases = (subprocess.CompletedProcess([], 1, b''), OSError('Wine unavailable'), subprocess.TimeoutExpired('tasklist', 10))
        for result in cases:
            options = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
            with self.subTest(result=result), mock.patch.object(app.subprocess, 'run', **options):
                self.desktop.checking = True
                self.desktop.check_client()
                self.assertEqual([event[0] for event in self.events()], ['client_check_done'])
                self.assertTrue(self.desktop.checking)

    def test_slow_taskkill_runs_off_ui_thread_and_holds_restart_until_completion(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        ui_thread = threading.get_ident()
        worker_threads = []
        ui_updates = []
        self.desktop._sync_controls.side_effect = lambda: ui_updates.append(threading.get_ident())
        def taskkill(state):
            worker_threads.append(threading.get_ident())
            entered.set()
            self.assertTrue(release.wait(3))
            return ''
        client = self.desktop.client = mock.Mock()
        helper = self.desktop.helper = mock.Mock()
        helper.poll.return_value = None
        descriptor = self.desktop.lock = os.open(self.desktop.state / 'desktop.lock', os.O_WRONLY | os.O_CREAT, 0o600)
        self.desktop.state.joinpath('desktop.lease').write_text('run\n')
        with mock.patch.object(app, 'stop_client', side_effect=taskkill):
            self.desktop.request_stop()
            self.assertTrue(entered.wait(3))
            self.assertTrue(self.desktop._stopping)
            self.assertFalse(self.desktop.state.joinpath('desktop.lease').exists())
            self.assertIs(self.desktop.client, client)
            self.assertIs(self.desktop.helper, helper)
            os.fstat(descriptor)
            with mock.patch.object(app.subprocess, 'Popen') as launch:
                self.desktop.launch()
                launch.assert_not_called()
            self.assertTrue(self.desktop.events.empty())
            release.set()
            self.complete_worker()
        self.assertNotEqual(worker_threads, [ui_thread])
        self.assertTrue(ui_updates)
        self.assertEqual(set(ui_updates), {ui_thread})
        self.assertIsNone(self.desktop.client)
        self.assertIsNone(self.desktop.helper)
        self.assertIsNone(self.desktop.lock)
        with self.assertRaises(OSError): os.fstat(descriptor)
        helper.wait.assert_called_once_with(timeout=10)
        self.desktop.window.destroy.assert_not_called()

    def test_taskkill_failure_removes_lease_but_preserves_lock_and_client_for_retry(self):
        for failure in (subprocess.TimeoutExpired('taskkill', 15), OSError('Wine unavailable'),
                        'Не удалось подтвердить закрытие ExitLag.'):
            with self.subTest(failure=failure):
                self.desktop._stopping = False
                self.desktop._stop_failed = False
                self.desktop._closing = False
                self.desktop.client = client = mock.Mock()
                self.desktop.helper = None
                descriptor = self.desktop.lock = os.open(self.desktop.state / 'desktop.lock', os.O_WRONLY | os.O_CREAT, 0o600)
                lease = self.desktop.state / 'desktop.lease'; lease.write_text('run\n')
                options = {'side_effect': failure} if isinstance(failure, Exception) else {'return_value': failure}
                with mock.patch.object(app, 'stop_client', **options):
                    self.desktop.request_stop()
                    self.complete_worker()
                self.assertFalse(lease.exists())
                self.assertIs(self.desktop.client, client)
                self.assertEqual(self.desktop.lock, descriptor)
                os.fstat(descriptor)
                self.assertFalse(self.desktop._stopping)
                with mock.patch.object(app.subprocess, 'Popen') as launch:
                    self.desktop.launch()
                    launch.assert_not_called()
                with mock.patch.object(app, 'stop_client', return_value=''):
                    self.desktop.request_stop()
                    self.complete_worker()
                self.assertIsNone(self.desktop.client)
                self.assertIsNone(self.desktop.lock)

    def test_supervisor_timeout_does_not_recreate_lease_or_allow_restart(self):
        helper = self.desktop.helper = mock.Mock()
        helper.poll.return_value = None
        helper.wait.side_effect = subprocess.TimeoutExpired('supervisor', 10)
        lease = self.desktop.state / 'desktop.lease'; lease.write_text('run\n')
        descriptor = self.desktop.lock = os.open(self.desktop.state / 'desktop.lock', os.O_WRONLY | os.O_CREAT, 0o600)
        self.desktop.request_stop()
        self.complete_worker()
        self.desktop.poll()
        self.assertFalse(lease.exists(), 'failed stop must not restore routing lease')
        self.assertIs(self.desktop.helper, helper)
        self.assertEqual(self.desktop.lock, descriptor)
        helper.wait.side_effect = None
        self.desktop.request_stop()
        self.complete_worker()
        self.assertIsNone(self.desktop.lock)

    def test_close_waits_asynchronously_for_stop_completion(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        self.desktop.client = mock.Mock()
        def taskkill(state):
            entered.set(); self.assertTrue(release.wait(3)); return ''
        with mock.patch.object(app, 'stop_client', side_effect=taskkill):
            self.desktop.close()
            self.assertTrue(entered.wait(3))
            self.desktop.window.destroy.assert_not_called()
            release.set(); self.complete_worker()
        self.desktop.window.destroy.assert_called_once_with()
        self.desktop.tasks.close.assert_called_once_with()

    def test_stale_client_query_after_restart_cannot_stop_new_session(self):
        import threading
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def query(state):
            entered.set(); self.assertTrue(release.wait(3)); return False
        with mock.patch.object(app, 'client_present', side_effect=query):
            worker = threading.Thread(target=self.desktop.check_client)
            worker.start(); self.assertTrue(entered.wait(3))
            self.desktop._session_generation += 1
            self.desktop.checking = True
            release.set(); worker.join(timeout=3)
        with mock.patch.object(self.desktop, 'request_stop') as stop:
            self.desktop.poll()
        stop.assert_not_called()
        self.assertTrue(self.desktop.checking, 'old done must not clear a new query')

    def test_udp_is_an_explicit_supervisor_flag_and_defaults_off(self):
        command = self.desktop._helper_command()
        self.assertNotIn('--udp', command)
        self.desktop.udp_enabled = mock.Mock(get=mock.Mock(return_value=False))
        self.assertEqual(self.desktop._helper_command(), command)
        self.desktop.udp_enabled.get.return_value = True
        self.assertEqual(self.desktop._helper_command(), command + ['--udp'])
        self.assertEqual(command[0:3], ['pkexec', '/usr/bin/python3', '-I'])
        self.assertEqual(command[command.index('--map') + 1], str(self.desktop.state / 'games.map'))

    def test_client_environment_removes_inherited_routing_and_wine_overrides(self):
        inherited = {'EXITLAG_NETD': 'malicious', 'EXITLAG_NETD_TOKEN': 'oldsecret',
                     'EXITLAG_IDENTITY_MAP': '/untrusted.map', 'WINEDLLPATH': '/untrusted',
                     'WINELOADER': '/untrusted', 'QT_OPENGL': 'old', 'QT_QUICK_BACKEND': 'old'}
        with mock.patch.dict(os.environ, inherited):
            env = app.environment(self.desktop.state)
            active = app.environment(self.desktop.state, Path('/run/approved.token'))
        for key in inherited: self.assertNotIn(key, env)
        self.assertEqual(env['WINEPREFIX'], str(self.desktop.state / 'prefix'))
        self.assertEqual(active['EXITLAG_NETD'], '127.0.0.1:51900')
        self.assertEqual(active['EXITLAG_NETD_TOKEN'], 'Z:/run/approved.token')
        for key in ('EXITLAG_IDENTITY_MAP', 'WINEDLLPATH', 'WINELOADER', 'QT_OPENGL', 'QT_QUICK_BACKEND'):
            self.assertNotIn(key, active)

    def test_nonzero_taskkill_accepts_independently_verified_absent_client(self):
        import desktop_session
        absent = subprocess.CompletedProcess([], 0, b'INFO: No tasks are running')
        with mock.patch.object(app.subprocess, 'run', side_effect=[
                subprocess.CompletedProcess([], 128), absent]) as run:
            self.assertEqual(desktop_session.stop_client(self.desktop.state), '')
        self.assertEqual(run.call_args_list[0].args[0][1:],
                         ['taskkill.exe', '/IM', 'ExitLag.exe', '/F'])
        self.assertEqual(run.call_args_list[1].args[0][1], 'tasklist.exe')

    def test_nonzero_taskkill_keeps_warning_when_presence_is_unknown_or_live(self):
        import desktop_session
        for listing in (subprocess.CompletedProcess([], 1, b''),
                        subprocess.CompletedProcess([], 0, b'ExitLag.exe 123 Console')):
            with self.subTest(listing=listing), mock.patch.object(app.subprocess, 'run',
                    side_effect=[subprocess.CompletedProcess([], 128), listing]):
                self.assertTrue(desktop_session.stop_client(self.desktop.state))

    def controls(self, running=False, configured=True, mappings=True):
        for name in ('launch_button', 'manage_button', 'udp_toggle',
                     'transport_status', 'session_status', 'relay_status'):
            setattr(self.desktop, name, mock.Mock())
        self.desktop._sync_controls = app.Desktop._sync_controls.__get__(self.desktop)
        self.desktop.busy = False
        self.desktop.helper = mock.Mock() if running else None
        self.desktop.client = None
        self.desktop._setup_ready = configured
        self.desktop.mapping_rows = {'game': 'entry'} if mappings else {}
        self.desktop.udp_enabled = mock.Mock(get=mock.Mock(return_value=False))

    def test_udp_control_is_locked_during_authorization_and_running_session(self):
        self.controls(running=True)
        self.desktop._sync_controls()
        self.desktop.udp_toggle.state.assert_called_with(['disabled'])
        self.desktop.launch_button.configure.assert_called_with(text='Остановить')
        self.desktop.launch_button.state.assert_called_with(['!disabled'])
        self.desktop.relay_status.set.assert_called_with('Маршрут не подтверждён')
        self.desktop.session_status.set.assert_called_with('Запуск')
        self.desktop.client = mock.Mock()
        self.desktop._sync_controls()
        self.desktop.session_status.set.assert_called_with('Клиент запущен')
        self.desktop.relay_status.set.assert_called_with('Маршрут не подтверждён')

    def test_primary_action_is_locked_while_stop_is_in_progress(self):
        self.controls(running=True)
        self.desktop._stopping = True
        self.desktop._sync_controls()
        self.desktop.launch_button.state.assert_called_with(['disabled'])
        self.desktop.manage_button.state.assert_called_with(['disabled'])
        self.desktop.udp_toggle.state.assert_called_with(['disabled'])
        self.desktop.session_status.set.assert_called_with('Остановка')

    def test_udp_control_requires_completed_setup_and_saved_games(self):
        for configured, mappings, ready in ((False, False, False), (False, True, False),
                                            (True, False, False), (True, True, True)):
            with self.subTest(configured=configured, mappings=mappings):
                self.controls(configured=configured, mappings=mappings)
                self.desktop._sync_controls()
                self.desktop.udp_toggle.state.assert_called_with(['!disabled'] if ready else ['disabled'])

    def test_stopping_routing_requests_async_stop_and_keeps_dashboard_visible(self):
        with mock.patch.object(self.desktop, 'request_stop') as stop:
            self.desktop.stop_routing()
        stop.assert_called_once_with()
        self.desktop.window.deiconify.assert_called_once_with()
        self.desktop.window.destroy.assert_not_called()

    def test_setup_in_progress_does_not_allow_session_stop_button(self):
        self.desktop.busy = True
        with mock.patch.object(self.desktop, 'request_stop') as stop:
            self.desktop.stop_routing()
        stop.assert_not_called()
        self.desktop.window.deiconify.assert_not_called()


support_spec = importlib.util.spec_from_file_location(
    'desktop_support_tests', ROOT / 'installers/linux/desktop_support.py')
support = importlib.util.module_from_spec(support_spec)
support_spec.loader.exec_module(support)


class DesktopPresentation(unittest.TestCase):
    def test_process_presence_never_confirms_a_route(self):
        for helper in (False, True):
            for client in (False, True):
                for ready in (False, True):
                    with self.subTest(helper=helper, client=client, ready=ready):
                        view = support.session_view(helper_running=helper,
                            client_running=client, backend_ready=ready)
                        self.assertFalse(view.can_confirm_route)
                        self.assertEqual(view.route, 'Маршрут не подтверждён')
        self.assertEqual(support.session_view().state, 'Остановлено')
        self.assertEqual(support.session_view(starting=True).state, 'Запуск')
        self.assertEqual(support.session_view(client_running=True).state, 'Клиент запущен')
        self.assertEqual(support.session_view(stopping=True).state, 'Остановка')
        self.assertEqual(support.session_view(client_running=True, error='failure').state, 'Ошибка')

    def test_supervisor_is_distinguished_from_backend_readiness(self):
        self.assertIn('Supervisor', support.session_view(helper_running=True).backend)
        self.assertEqual(support.session_view(helper_running=True, backend_ready=True).backend,
                         'Готовность получена')
        self.assertEqual(support.session_view(backend_ready=True).backend, 'Не запущен')

    def test_multiline_secret_values_are_not_displayed(self):
        safe = support.redact('password:\n  private-multiline-canary\n\nordinary diagnostic')
        self.assertNotIn('private-multiline-canary', safe)
        self.assertIn('ordinary diagnostic', safe)

    def test_display_paths_do_not_expose_directories(self):
        for path, name in (('/home/Private User/games/PEAK.exe', 'PEAK.exe'),
                           (r'C:\Users\Private User\PEAK.exe', 'PEAK.exe')):
            with self.subTest(path=path):
                self.assertEqual(support.display_path(path), '…/' + name)
                self.assertNotIn('Private User', support.display_path(path))
        self.assertEqual(support.display_path(None), 'Недоступно')

    def test_redaction_removes_secrets_paths_addresses_and_controls(self):
        raw = '\n'.join((
            'Authorization: Bearer private-bearer-value',
            'EXITLAG_NETD_TOKEN=private-token-value',
            'password=private-password-value',
            'session_id=private-session-value',
            'source=/home/Private User/a game/bin/PEAK.exe more text',
            r'file=C:\Users\Private User\a game\PEAK.exe trailing text',
            r'file=\\private-server\private-share\PEAK.exe',
            'peer=192.168.42.17 and 2001:db8::5',
            'id=0123456789abcdef0123456789abcdef',
            'mail=private.user@example.invalid',
            'hello\x1b[31m\x00\u202e'))
        safe = support.redact(raw)
        for secret in ('private-', 'Private User', 'private-server',
                       'private-share', '192.168.42.17', '2001:db8::5',
                       '0123456789abcdef0123456789abcdef', 'example.invalid',
                       '\x1b', '\x00', '\u202e'):
            with self.subTest(secret=secret): self.assertNotIn(secret, safe)
        self.assertEqual(support.redact(safe), safe)


class DesktopDiagnostics(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='bridge-diagnostics-')
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.log = self.directory / 'client.log'

    def private_log(self, data):
        self.log.write_bytes(data)
        self.log.chmod(0o600)

    def test_private_log_read_is_bounded_and_redacted(self):
        self.private_log(b'old line\n' + b'x' * 50000 + b'\npassword=private-canary\n\nfinal visible line\n')
        result = support.read_log_tail(self.log, expected_uid=os.getuid(), max_bytes=128)
        self.assertLessEqual(len(result.encode()), 512)
        self.assertIn('final visible line', result)
        self.assertNotIn('old line', result)
        self.assertNotIn('private-canary', result)

    def test_windows_utf16_log_secrets_are_redacted(self):
        text = 'password=private-canary\nready\n'
        for encoding in ('utf-16', 'utf-16le', 'utf-16be'):
            with self.subTest(encoding=encoding):
                self.private_log(text.encode(encoding))
                safe = support.read_log_tail(self.log, expected_uid=os.getuid())
                self.assertNotIn('private-canary', safe)
                self.assertIn('ready', safe)
        self.private_log(('password=' + 'private-canary' * 300 + '\n\nready\n').encode('utf-16'))
        self.assertEqual(support.read_log_tail(self.log, expected_uid=os.getuid(), max_bytes=65), 'ready')

    def test_partial_first_line_never_reveals_secret_tail(self):
        self.private_log(b'password=' + b'secret-value-' * 500)
        self.assertEqual(support.read_log_tail(self.log, expected_uid=os.getuid(), max_bytes=64), '')

    def test_truncated_multiline_secret_requires_a_complete_record_boundary(self):
        self.private_log(b'password:\n' + b'padding-value\n' * 100 + b'private-multiline-canary\n\nordinary record\n')
        safe = support.read_log_tail(self.log, expected_uid=os.getuid(), max_bytes=80)
        self.assertNotIn('private-multiline-canary', safe)
        self.assertIn('ordinary record', safe)
        self.private_log(b'password:\n' + b'padding-value\n' * 100 + b'private-multiline-canary\n')
        self.assertEqual(support.read_log_tail(self.log, expected_uid=os.getuid(), max_bytes=80), '')
        self.assertNotIn('api-private-canary', support.redact('api_key=api-private-canary'))

    def test_links_fifo_wrong_owner_and_public_logs_are_rejected(self):
        self.private_log(b'fixture')
        with self.assertRaises(ValueError):
            support.read_log_tail(self.log, expected_uid=os.getuid() + 1)
        self.log.chmod(0o644)
        with self.assertRaises(ValueError): support.read_log_tail(self.log, expected_uid=os.getuid())
        self.log.chmod(0o600)
        other = self.directory / 'other'
        os.link(self.log, other)
        with self.assertRaises(ValueError): support.read_log_tail(self.log, expected_uid=os.getuid())
        other.unlink()
        self.log.rename(other)
        self.log.symlink_to(other)
        with self.assertRaises(OSError): support.read_log_tail(self.log, expected_uid=os.getuid())
        self.log.unlink()
        os.mkfifo(self.log, 0o600)
        with self.assertRaises(ValueError): support.read_log_tail(self.log, expected_uid=os.getuid())

    def test_directory_symlink_and_writable_parent_are_refused(self):
        self.private_log(b'fixture')
        alias = self.directory / 'alias'
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(OSError):
            support.read_log_tail(alias / 'client.log', expected_uid=os.getuid())
        self.directory.chmod(0o777)
        with self.assertRaises(ValueError): support.read_log_tail(self.log, expected_uid=os.getuid())

    def test_invalid_read_limits_are_rejected(self):
        for limit in (0, 65537, -1, True, '1024'):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                support.read_log_tail(self.log, expected_uid=os.getuid(), max_bytes=limit)

    def test_client_log_writer_rejects_fifo_links_and_public_files(self):
        os.mkfifo(self.log, 0o600)
        with self.assertRaises(OSError): app.open_client_log(self.log)
        self.log.unlink()
        self.private_log(b'fixture')
        self.log.chmod(0o644)
        with self.assertRaises(ValueError): app.open_client_log(self.log)
        self.log.chmod(0o600)
        other = self.directory / 'linked'
        os.link(self.log, other)
        with self.assertRaises(ValueError): app.open_client_log(self.log)
        other.unlink(); self.log.rename(other); self.log.symlink_to(other)
        with self.assertRaises(OSError): app.open_client_log(self.log)

    def test_client_log_writer_creates_private_append_only_target(self):
        fd = app.open_client_log(self.log)
        try:
            os.write(fd, b'fixture')
            self.assertFalse(os.get_inheritable(fd))
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o600)
        finally: os.close(fd)
        self.assertEqual(self.log.read_bytes(), b'fixture')

    def test_snapshot_reads_only_known_logs_and_never_token_contents(self):
        self.private_log(b'password=private-canary\nready\n')
        original = support.read_log_tail
        observed = []
        def read(path, **kwargs):
            observed.append(Path(path))
            if Path(path) == self.log: return original(path, **kwargs)
            raise PermissionError('private host path must not be shown')
        with mock.patch.object(support, 'read_log_tail', side_effect=read):
            text = support.diagnostics_snapshot(self.directory)
        self.assertEqual(observed, [self.log,
            Path('/run') / f'exitlag-bridge-{os.getuid()}' / 'backend.log'])
        self.assertNotIn('private-canary', text)
        self.assertNotIn(str(self.directory), text)
        self.assertIn('повышение прав не запрашивается', text)
        self.assertIn('не измеряются', text)
        self.assertNotIn('private host path', text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
