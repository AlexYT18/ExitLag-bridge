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
        self.desktop.client = mock.Mock()
        self.desktop.helper = mock.Mock()
        self.desktop.message = mock.Mock()
        self.desktop.lock = None

    def test_live_client_is_preserved_for_windows_console_encodings(self):
        listing = '\r\nExitLag.exe             123 Console       1 100,000 K\r\n'
        for encoding in ('utf-8', 'utf-16', 'utf-16le', 'utf-16be'):
            # A UTF-16BE byte stream needs the BOM to declare its endianness.
            data = listing.encode(encoding)
            if encoding == 'utf-16be':
                data = b'\xfe\xff' + data
            with self.subTest(encoding=encoding), mock.patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, data)):
                self.desktop.checking = True
                self.desktop.check_client()
                self.assertTrue(self.desktop.events.empty())
                self.assertFalse(self.desktop.checking)

    def test_successful_query_of_absent_client_requests_close(self):
        absent = 'INFO: No tasks are running which match the specified criteria.\r\n'
        with mock.patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, absent.encode('utf-16'))):
            self.desktop.check_client()
        self.assertEqual(self.desktop.events.get_nowait(), ('client_closed',))
        self.assertFalse(self.desktop.checking)

    def test_failed_or_timed_out_query_does_not_claim_client_exit(self):
        cases = (subprocess.CompletedProcess([], 1, b''), OSError('Wine unavailable'), subprocess.TimeoutExpired('tasklist', 10))
        for result in cases:
            options = {'side_effect': result} if isinstance(result, Exception) else {'return_value': result}
            with self.subTest(result=result), mock.patch.object(app.subprocess, 'run', **options):
                self.desktop.checking = True
                self.desktop.check_client()
                self.assertTrue(self.desktop.events.empty())
                self.assertFalse(self.desktop.checking)

    def test_taskkill_failure_still_releases_lease_and_local_lock(self):
        for error in (subprocess.TimeoutExpired('taskkill', 15), OSError('Wine unavailable')):
            with self.subTest(error=error):
                lease = self.desktop.state / 'desktop.lease'
                lease.write_text('run\n')
                descriptor = os.open(self.desktop.state / 'desktop.lock', os.O_WRONLY | os.O_CREAT, 0o600)
                self.desktop.lock = descriptor
                self.desktop.client = mock.Mock()
                self.desktop.helper = mock.Mock()
                with mock.patch.object(app.subprocess, 'run', side_effect=error) as run:
                    self.desktop.stop_session()
                self.assertFalse(lease.exists())
                self.assertIsNone(self.desktop.client)
                self.assertIsNone(self.desktop.helper)
                self.assertIsNone(self.desktop.lock)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
                self.assertEqual(run.call_args.args[0][1:], ['taskkill.exe', '/IM', 'ExitLag.exe', '/F'])
                self.assertEqual(run.call_args.kwargs['env']['WINEPREFIX'], str(self.desktop.state / 'prefix'))
                self.desktop.message.set.assert_called()

    def test_close_destroys_window_after_taskkill_timeout(self):
        self.desktop.busy = False
        self.desktop.window = mock.Mock()
        with mock.patch.object(app.subprocess, 'run', side_effect=subprocess.TimeoutExpired('taskkill', 15)):
            self.desktop.close()
        self.desktop.window.destroy.assert_called_once_with()

    def test_udp_is_an_explicit_supervisor_flag_and_defaults_off(self):
        command = self.desktop._helper_command()
        self.assertNotIn('--udp', command)
        self.desktop.udp_enabled = mock.Mock(get=mock.Mock(return_value=False))
        self.assertEqual(self.desktop._helper_command(), command)
        self.desktop.udp_enabled.get.return_value = True
        self.assertEqual(self.desktop._helper_command(), command + ['--udp'])
        self.assertEqual(command[0:3], ['pkexec', '/usr/bin/python3', '-I'])
        self.assertEqual(command[command.index('--map') + 1], str(self.desktop.state / 'games.map'))

    def controls(self, running=False, configured=True, mappings=True):
        for name in ('launch_button', 'stop_button', 'manage_button', 'udp_toggle',
                     'transport_status', 'session_status', 'relay_status'):
            setattr(self.desktop, name, mock.Mock())
        self.desktop.busy = False
        self.desktop.helper = mock.Mock() if running else None
        self.desktop.client = None
        self.desktop.configured = mock.Mock(return_value=configured)
        self.desktop.mapping_rows = {'game': 'entry'} if mappings else {}
        self.desktop.udp_enabled = mock.Mock(get=mock.Mock(return_value=False))

    def test_udp_control_is_locked_during_authorization_and_running_session(self):
        self.controls(running=True)
        self.desktop._sync_controls()
        self.desktop.udp_toggle.state.assert_called_with(['disabled'])
        self.desktop.launch_button.state.assert_called_with(['disabled'])
        self.desktop.stop_button.state.assert_called_with(['!disabled'])
        self.desktop.relay_status.set.assert_called_with('Not verified')
        self.desktop.session_status.set.assert_called_with('Authorizing / starting')
        self.desktop.client = mock.Mock()
        self.desktop._sync_controls()
        self.desktop.session_status.set.assert_called_with('Client started; route not verified')
        self.desktop.relay_status.set.assert_called_with('Not verified')

    def test_udp_control_requires_completed_setup_and_saved_games(self):
        for configured, mappings, ready in ((False, False, False), (False, True, False),
                                            (True, False, False), (True, True, True)):
            with self.subTest(configured=configured, mappings=mappings):
                self.controls(configured=configured, mappings=mappings)
                self.desktop._sync_controls()
                self.desktop.udp_toggle.state.assert_called_with(['!disabled'] if ready else ['disabled'])

    def test_stopping_routing_closes_existing_session_and_keeps_dashboard_visible(self):
        self.desktop.busy = False
        self.desktop.window = mock.Mock()
        with mock.patch.object(self.desktop, 'stop_session') as stop:
            self.desktop.stop_routing()
        stop.assert_called_once_with()
        self.desktop.window.deiconify.assert_called_once_with()
        self.desktop.window.destroy.assert_not_called()
        self.desktop.message.set.assert_called_with('Routing stopped. Reconnect existing game sessions before testing a different mode.')

    def test_setup_in_progress_does_not_allow_session_stop_button(self):
        self.desktop.busy = True
        self.desktop.window = mock.Mock()
        with mock.patch.object(self.desktop, 'stop_session') as stop:
            self.desktop.stop_routing()
        stop.assert_not_called()
        self.desktop.window.deiconify.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2)
