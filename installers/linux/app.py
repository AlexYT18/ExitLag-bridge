#!/usr/bin/python3
"""Desktop setup and launcher; the vendor client always runs as the user.
SPDX-License-Identifier: GPL-3.0-only
"""
import argparse
import atexit
import fcntl
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
import webbrowser

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'installers'))
from bridge_setup.core import Setup, console_output, default_state, find_client
from bridge_setup.util import State, private_json, read_private


def starttime(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]


class Desktop:
    def __init__(self, manage=False):
        if os.geteuid() == 0:
            raise SystemExit('Open ExitLag Bridge from your desktop as the game user')
        self.state = default_state()
        self.window = tk.Tk()
        self.window.title('ExitLag Bridge')
        self.window.geometry('1000x660')
        self.window.minsize(820, 570)
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        signal.signal(signal.SIGTERM, lambda *_: self.window.after(0, self.close))
        self.events = queue.Queue()
        self.busy = False
        self.client = self.helper = None
        self.lock = None
        self.started = None
        self.last_check = 0
        self.checking = False
        self.message = tk.StringVar(value='Download the official Windows installer, then choose its .exe.')
        self.udp_enabled = tk.BooleanVar(value=False)
        self.selected_game = tk.StringVar(value='Choose a game')
        self.selected_details = tk.StringVar(value='Add a running game to capture its executable and Wine/Proton prefix.')
        self.session_status = tk.StringVar(value='Stopped')
        self.relay_status = tk.StringVar(value='Not verified')
        self.transport_status = tk.StringVar(value='TCP')
        self.mapping_rows = {}
        self._build_ui()
        self.refresh_game_list()
        self.window.after(300, self.poll)
        if manage:
            self.window.after(100, self.games)
        elif self.configured():
            self.message.set('Ready. Choose a game, then launch ExitLag and apply its route in the official client.')

    def _build_ui(self):
        shell = ttk.Frame(self.window); shell.pack(fill='both', expand=True)
        sidebar = ttk.Frame(shell, padding=18); sidebar.pack(side='left', fill='y')
        sidebar.configure(width=245)
        ttk.Label(sidebar, text='ExitLag Bridge', font=('', 18, 'bold')).pack(anchor='w')
        ttk.Label(sidebar, text='Linux compatibility layer').pack(anchor='w', pady=(4, 22))
        ttk.Label(sidebar, text='MY GAMES', font=('', 10, 'bold')).pack(anchor='w')
        self.game_list = ttk.Treeview(sidebar, show='tree', selectmode='browse', height=14)
        self.game_list.column('#0', width=205, minwidth=150)
        self.game_list.pack(fill='both', expand=True, pady=8)
        self.game_list.bind('<<TreeviewSelect>>', self.select_game)
        self.manage_button = ttk.Button(sidebar, text='Add / manage games', command=self.games)
        self.manage_button.pack(fill='x', pady=(4, 6))
        ttk.Button(sidebar, text='Refresh games', command=self.refresh_game_list).pack(fill='x', pady=(0, 16))
        ttk.Button(sidebar, text='Client setup', command=lambda: self.show_page('setup')).pack(fill='x', pady=(0, 6))
        ttk.Button(sidebar, text='Game dashboard', command=lambda: self.show_page('games')).pack(fill='x')
        ttk.Button(sidebar, text='Quit', command=self.close).pack(fill='x', pady=(16, 0))
        ttk.Separator(shell, orient='vertical').pack(side='left', fill='y')
        content = ttk.Frame(shell, padding=24); content.pack(side='left', fill='both', expand=True)
        self.pages = {name: ttk.Frame(content) for name in ('games', 'setup')}
        game = self.pages['games']
        ttk.Label(game, textvariable=self.selected_game, font=('', 24, 'bold')).pack(anchor='w')
        ttk.Label(game, textvariable=self.selected_details, wraplength=640).pack(anchor='w', pady=(10, 24))
        session = ttk.LabelFrame(game, text='Session', padding=16); session.pack(fill='x')
        for row, (label, value) in enumerate((('Helper / client', self.session_status), ('Traffic mode', self.transport_status), ('Relay traffic', self.relay_status))):
            ttk.Label(session, text=label).grid(row=row, column=0, sticky='w', padx=(0, 28), pady=5)
            ttk.Label(session, textvariable=value).grid(row=row, column=1, sticky='w', pady=5)
        self.udp_toggle = ttk.Checkbutton(game, text='Experimental UDP', variable=self.udp_enabled, command=self._sync_controls)
        self.udp_toggle.pack(anchor='w', pady=(20, 6))
        ttk.Label(game, text='UDP must be verified for each game. A detected process does not prove relay traffic or successful gameplay.', wraplength=640).pack(anchor='w')
        ttk.Label(game, text='Authentication, relay selection and route decisions remain in the official ExitLag client.', wraplength=640).pack(anchor='w', pady=(12, 20))
        ttk.Label(game, text='All saved mappings apply to this session. Choose active game routes in ExitLag.', wraplength=640).pack(anchor='w', pady=(0, 12))
        actions = ttk.Frame(game); actions.pack(fill='x')
        self.launch_button = ttk.Button(actions, text='Launch ExitLag', command=self.launch); self.launch_button.pack(side='left')
        self.stop_button = ttk.Button(actions, text='Stop routing', command=self.stop_routing); self.stop_button.pack(side='left', padx=10)
        ttk.Label(game, textvariable=self.message, wraplength=640).pack(anchor='w', pady=(20, 0))
        setup = self.pages['setup']
        ttk.Label(setup, text='Official client setup', font=('', 22, 'bold')).pack(anchor='w')
        ttk.Label(setup, text='Download the original ExitLag Windows installer, then choose its .exe. Sign in inside the official client using your own account.', wraplength=640).pack(anchor='w', pady=(16, 20))
        buttons = ttk.Frame(setup); buttons.pack(anchor='w')
        ttk.Button(buttons, text='Download from ExitLag', command=lambda: webbrowser.open('https://www.exitlag.com/download')).pack(side='left', padx=(0, 8))
        self.choose = ttk.Button(buttons, text='Choose installer...', command=self.install); self.choose.pack(side='left')
        ttk.Label(setup, text='Review the vendor terms. Use C:\\ExitLag and leave Launch ExitLag unchecked in the installer.', wraplength=640).pack(anchor='w', pady=(24, 12))
        ttk.Label(setup, text='The documented Windows NDIS warning can be acknowledged because this bridge supplies native routing. Other setup failures must be investigated.', wraplength=640).pack(anchor='w')
        ttk.Label(setup, textvariable=self.message, wraplength=640).pack(anchor='w', pady=(24, 0))
        self.show_page('games')

    def show_page(self, name):
        for page in self.pages.values(): page.pack_forget()
        self.pages[name].pack(fill='both', expand=True)

    def refresh_game_list(self):
        sys.path.insert(0, str(Path(__file__).parent))
        from game_picker import MappingController, load_map
        previous = self.game_list.selection()
        try:
            rows = MappingController(load_map(self.state / 'games.map')).rows()
        except (OSError, ValueError) as error:
            self.message.set('Game settings: ' + str(error)); rows = []
        self.game_list.delete(*self.game_list.get_children())
        self.mapping_rows = {str(row[0]): row for row in rows}
        for key, row in self.mapping_rows.items():
            self.game_list.insert('', 'end', iid=key, text=row[1])
        choice = previous[0] if previous and previous[0] in self.mapping_rows else next(iter(self.mapping_rows), None)
        if choice is not None:
            self.game_list.selection_set(choice)
            self.select_game()
        else:
            self.selected_game.set('Choose a game')
            self.selected_details.set('Add a running game to capture its executable and Wine/Proton prefix.')
        self._sync_controls()

    def select_game(self, _event=None):
        selected = self.game_list.selection()
        if not selected or selected[0] not in self.mapping_rows: return
        _index, name, kind, identity, _source = self.mapping_rows[selected[0]]
        self.selected_game.set(name)
        self.selected_details.set(f'{kind}\nWindows identity: {identity}')
        self.show_page('games')

    def _sync_controls(self):
        if not hasattr(self, 'launch_button'): return
        running = bool(self.helper or self.client)
        self.launch_button.state(['disabled'] if self.busy or running else ['!disabled'])
        self.stop_button.state(['!disabled'] if running and not self.busy else ['disabled'])
        self.manage_button.state(['disabled'] if self.busy or running else ['!disabled'])
        ready = not self.busy and not running and self.configured() and bool(self.mapping_rows)
        self.udp_toggle.state(['!disabled'] if ready else ['disabled'])
        self.transport_status.set('TCP + UDP (experimental)' if self.udp_enabled.get() else 'TCP')
        self.session_status.set('Client started; route not verified' if self.client else 'Authorizing / starting' if self.helper else 'Stopped')
        self.relay_status.set('Not verified')

    def _helper_command(self):
        command = ['pkexec', '/usr/bin/python3', '-I', str(ROOT / 'installers/linux/run_root.py'), '--uid', str(os.getuid()), '--parent', str(os.getpid()), '--map', str(self.state / 'games.map'), '--lease', str(self.state / 'desktop.lease')]
        option = getattr(self, 'udp_enabled', None)
        if option is not None and option.get(): command.append('--udp')
        return command

    def stop_routing(self):
        if self.busy: return
        self.stop_session()
        self.message.set('Routing stopped. Reconnect existing game sessions before testing a different mode.')
        self.window.deiconify()

    def configured(self):
        try:
            return State(self.state).load().get('complete') and find_client(self.state / 'prefix') is not None
        except (OSError, ValueError):
            return False

    def install(self):
        if self.busy or self.client:
            return
        selected = filedialog.askopenfilename(title='Official ExitLag Windows installer', filetypes=[('Windows executable', '*.exe')])
        if not selected:
            return
        self.busy = True; self.choose.state(['disabled'])
        def work():
            try:
                Setup(self.state, ROOT / 'installers/payloads', emit=lambda stage, message: self.events.put(message)).run(Path(selected))
            except Exception as error:
                self.events.put('Setup stopped: ' + str(error))
            finally:
                self.events.put(None)
        threading.Thread(target=work, daemon=True).start()

    def games(self):
        if self.busy or self.helper:
            return
        try:
            State(self.state, create=True)
        except (OSError, ValueError) as error:
            messagebox.showerror('Setup directory', str(error)); return
        sys.path.insert(0, str(Path(__file__).parent))
        from game_picker import open_editor
        try:
            editor = open_editor(self.window, self.state / 'games.map', ROOT)
            editor.window.bind('<Destroy>', lambda event: self.window.after_idle(self.refresh_game_list) if event.widget is editor.window and self.window.winfo_exists() else None, add='+')
            return editor
        except (OSError, ValueError) as error:
            messagebox.showerror('Game settings', str(error), parent=self.window)

    def launch(self):
        if self.busy or self.helper:
            return
        if not self.configured():
            self.message.set('Complete setup using the official installer first.'); return
        if not (self.state / 'games.map').is_file():
            self.message.set('Configure the game you want to route first.'); self.games(); return
        self.lock = os.open(self.state / 'desktop.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock); self.lock = None
            self.message.set('ExitLag Bridge is already running.'); return
        private_json(self.state / 'desktop-session.json', dict(pid=os.getpid(), start=starttime(os.getpid())))
        leasefd = os.open(self.state / 'desktop.lease', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(leasefd, 'w') as output: output.write('run\n')
        self.started = time.time()
        self.helper = subprocess.Popen(self._helper_command(), stdin=subprocess.DEVNULL)
        self.message.set('Authorize routing in the system dialog. ExitLag will open when the helper is ready.')
        self._sync_controls()

    def poll(self):
        try:
            while True:
                value = self.events.get_nowait()
                if value == ('client_closed',):
                    self.stop_session()
                    self.window.destroy()
                    return
                elif value is None:
                    self.busy = False; self.choose.state(['!disabled'])
                else: self.message.set(value)
        except queue.Empty:
            pass
        if self.helper:
            (self.state / 'desktop.lease').touch()
            if self.helper.poll() is not None:
                self.message.set('Routing stopped or authorization was cancelled. You can retry Launch ExitLag.')
                self.stop_session()
                self.window.deiconify()
            elif not self.client:
                token = Path('/run/exitlag-linux/ipc.token')
                if token.exists() and token.stat().st_uid == os.getuid() and token.stat().st_mtime >= self.started:
                    client = find_client(self.state / 'prefix')
                    env = os.environ.copy()
                    for name in list(env):
                        if name.startswith('EXITLAG_') or name in ('WINEDLLPATH', 'WINELOADER', 'QT_QUICK_BACKEND', 'QT_OPENGL'):
                            env.pop(name, None)
                    env.update(WINEPREFIX=str(self.state / 'prefix'), WINEDEBUG='-all', QSG_RHI_BACKEND='opengl', EXITLAG_NETD='127.0.0.1:51900', EXITLAG_NETD_TOKEN='Z:' + str(token))
                    logfd = os.open(self.state / 'client.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
                    with os.fdopen(logfd, 'ab') as log:
                        self.client = subprocess.Popen([str(self.state / 'runtime/bin/wine'), str(client)], cwd=client.parent, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                    self.message.set('Helper ready and official client started. Select your game and apply its routes in ExitLag; relay traffic is not yet verified.')
                elif time.time() - self.started > 120:
                    self.message.set('The routing helper did not start. Close and try again.')
                    self.stop_session()
            elif time.time() - self.started > 25 and time.time() - self.last_check > 5 and not self.checking:
                self.last_check = time.time(); self.checking = True
                threading.Thread(target=self.check_client, daemon=True).start()
        self._sync_controls()
        self.window.after(500, self.poll)

    def check_client(self):
        try:
            env = os.environ.copy(); env.update(WINEPREFIX=str(self.state / 'prefix'), WINEDEBUG='-all')
            result = subprocess.run([str(self.state / 'runtime/bin/wine'), 'tasklist.exe', '/FI', 'IMAGENAME eq ExitLag.exe', '/NH'], env=env, capture_output=True, timeout=10)
            if result.returncode == 0 and b'exitlag.exe' not in console_output(result.stdout).lower():
                self.events.put(('client_closed',))
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            self.checking = False

    def stop_session(self):
        (self.state / 'desktop.lease').unlink(missing_ok=True)
        try:
            if self.client:
                env = os.environ.copy(); env.update(WINEPREFIX=str(self.state / 'prefix'), WINEDEBUG='-all')
                subprocess.run([str(self.state / 'runtime/bin/wine'), 'taskkill.exe', '/IM', 'ExitLag.exe', '/F'], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        except (OSError, subprocess.TimeoutExpired):
            self.message.set('ExitLag could not be closed automatically. Close its window if it is still open.')
        finally:
            self.client = None
            # Removing the lease stops the elevated supervisor independently of Wine.
            self.helper = None
            if self.lock is not None:
                os.close(self.lock); self.lock = None
            self._sync_controls()

    def close(self):
        if self.busy:
            messagebox.showinfo('Setup in progress', 'Finish or cancel the vendor installer before closing.'); return
        self.stop_session()
        self.window.destroy()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manage-games', action='store_true')
    parser.add_argument('--quit', action='store_true')
    args = parser.parse_args()
    if args.quit:
        try:
            record = read_private(default_state() / 'desktop-session.json')
            pid = record['pid']
            if (Path('/proc') / str(pid)).stat().st_uid == os.getuid() and starttime(pid) == record['start']:
                os.kill(pid, signal.SIGTERM)
        except (OSError, ValueError, KeyError):
            pass
        return
    Desktop(args.manage_games).window.mainloop()


if __name__ == '__main__':
    main()
