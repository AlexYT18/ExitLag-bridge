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
import stat
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
sys.path.insert(0, str(Path(__file__).parent))
from desktop_support import diagnostics_snapshot, display_path, redact, session_view
from desktop_session import client_present, environment, open_client_log, stop_client
from game_picker import MappingController, TaskQueue, load_map, visible_candidates


def starttime(pid):
    return (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()[19]


class Desktop:
    def __init__(self, manage=False):
        if os.geteuid() == 0:
            raise SystemExit('Open ExitLag Bridge from your desktop as the game user')
        self.state = default_state()
        self.window = tk.Tk()
        self.window.title('ExitLag Bridge')
        self.window.geometry(f'{min(1180, self.window.winfo_screenwidth()-40)}x{min(740, max(640, self.window.winfo_screenheight()-90))}')
        self.window.minsize(1040, 640)
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        signal.signal(signal.SIGTERM, lambda *_: self.window.after(0, self.close))
        self.events = queue.Queue()
        self.busy = False
        self.client = self.helper = None
        self.lock = None
        self.started = None
        self.last_check = 0
        self.checking = False
        self.message = tk.StringVar(value='Подготовьте официальный клиент и добавьте игру перед подключением.')
        self.udp_enabled = tk.BooleanVar(value=False)
        self.selected_game = tk.StringVar(value='Выберите игру')
        self.selected_details = tk.StringVar(value='Add a running game to capture its executable and Wine/Proton prefix.')
        self.session_status = tk.StringVar(value='Остановлено')
        self.relay_status = tk.StringVar(value='Маршрут не подтверждён')
        self.transport_status = tk.StringVar(value='TCP')
        self.mapping_rows = {}
        self._build_ui()
        self.refresh_game_list()
        self.window.after(100, self.poll)
        self.refresh_setup()
        if manage:
            self.window.after(100, self.games)

    def _build_ui(self):
        from desktop_ui import build
        self.tasks = TaskQueue()
        self.candidates = []
        self._scan_time = None
        self._setup_ready = False
        self._last_error = ''
        self._stopping = self._closing = self._backend_ready = self._stop_failed = False
        self._session_generation = 0
        for name, initial in (('backend_status', 'Остановлен'), ('client_status', 'Остановлен'),
                              ('saved_query', ''), ('process_query', ''), ('process_details', 'Выберите процесс из списка.'),
                              ('process_warning', ''), ('scan_status', 'Снимок процессов ещё не получен.'),
                              ('statistics', 'Сессия остановлена.')):
            setattr(self, name, tk.StringVar(master=self.window, value=initial))
        self.show_technical = tk.BooleanVar(master=self.window, value=False)
        build(self)

    def open_download(self):
        webbrowser.open('https://www.exitlag.com/download')

    def show_page(self, name):
        for page in self.pages.values(): page.pack_forget()
        self.pages[name].pack(fill='both', expand=True)
        if hasattr(self, 'page_title'):
            self.page_title.set(self.page_names[name])
            for key, button in self.nav_buttons.items():
                button.configure(style='Selected.Nav.TButton' if key == name else 'Nav.TButton')
        if name == 'games' and self._scan_time is None and not self.tasks.closed:
            self.scan_processes()

    def refresh_setup(self):
        def done(value, error):
            self._setup_ready = bool(value) if not error else False
            if error: self._error(error)
            self._sync_controls()
        self._submit('setup_status', self.configured, done)

    def _submit(self, kind, work, done):
        try:
            self.tasks.submit(kind, work, done)
            return True
        except (ValueError, RuntimeError) as error:
            self.message.set(redact(str(error)))
            return False

    def _error(self, error):
        self._last_error = redact(str(error))
        self.message.set('Ошибка: ' + self._last_error)
        self._sync_controls()

    def refresh_game_list(self):
        try:
            self.mapping_text = load_map(self.state / 'games.map')
            rows = MappingController(self.mapping_text).rows()
        except (OSError, ValueError) as error:
            self._error(error); rows = []; self.mapping_text = ''
        self.mapping_rows = {str(row[0]): row for row in rows}
        self.render_saved_games()
        self._sync_controls()

    def _mapped_candidates(self, row):
        fields = self.mapping_text.splitlines()[row[0]].split('\t')
        if row[2] == 'Wine / Proton' and len(fields) == 3:
            return [c for c in self.candidates if str(c.prefix) == row[4] and str(c.executable) == fields[2]]
        return [c for c in self.candidates if c.prefix is None and str(c.executable) == row[4]]

    def render_saved_games(self):
        old = self.game_list.selection()
        self.game_list.delete(*self.game_list.get_children())
        query = self.saved_query.get().casefold().strip()
        for key, row in self.mapping_rows.items():
            hints = ' '.join(str(c.steam_appid or '') for c in self._mapped_candidates(row))
            if not query or query in (row[1] + ' ' + hints).casefold():
                self.game_list.insert('', 'end', iid=key, text=row[1])
        available = self.game_list.get_children()
        choice = old[0] if old and old[0] in available else next(iter(available), None)
        if choice is not None:
            self.game_list.selection_set(choice); self.select_game()
        else:
            self.selected_game.set('Выберите игру')
            self.selected_details.set('Добавьте работающую игру в разделе «Игры».')

    def select_game(self, _event=None):
        selected = self.game_list.selection()
        if not selected or selected[0] not in self.mapping_rows: return
        row = self.mapping_rows[selected[0]]
        self.selected_game.set(redact(row[1]))
        fields = self.mapping_text.splitlines()[row[0]].split('\t')
        executable = fields[2] if len(fields) == 3 else row[4]
        candidates = self._mapped_candidates(row)
        pid = str(candidates[0].pid) if len(candidates) == 1 else 'Не обнаружен' if not candidates else 'Несколько процессов — уточните выбор'
        prefix = display_path(row[4]) if row[2] == 'Wine / Proton' else 'Не используется'
        self.selected_details.set(f'{row[2]}\nExecutable: {display_path(executable)}\nPID: {pid}\nPrefix: {prefix}\nIdentity: {display_path(row[3])}')

    def scan_processes(self):
        self.scan_button.state(['disabled'])
        self.scan_status.set('Чтение сетевых процессов…')
        def work():
            from bridge_setup.process_picker import ProcessPicker
            return ProcessPicker(ROOT / 'tools/discover-game-processes.py').list_candidates()
        def done(items, error):
            self.scan_button.state(['!disabled'])
            if error:
                self.scan_status.set(redact(str(error))); self.candidates = []; self._scan_time = None
            else:
                self.candidates = items; self._scan_time = time.monotonic()
                self.scan_status.set(f'Получен снимок: {len(items)} процессов. Перед сохранением владелец проверяется повторно.')
            self.render_processes(); self.render_saved_games()
        if not self._submit('process_scan', work, done):
            self.scan_button.state(['!disabled'])

    def render_processes(self):
        previous = self.process_tree.selection()
        self.process_tree.delete(*self.process_tree.get_children())
        for item in visible_candidates(self.candidates, self.process_query.get(), self.show_technical.get()):
            self.process_tree.insert('', 'end', iid=f'{item.pid}:{item.start_time}', values=(redact(item.name), item.pid, item.kind, '/'.join(item.transports).upper(), item.steam_appid or '—'))
        if previous and self.process_tree.exists(previous[0]):
            self.process_tree.selection_set(previous[0]); self.select_process()
        else:
            self.process_details.set('Выберите процесс из списка.')
            self.process_warning.set(''); self.add_process_button.state(['disabled'])

    def select_process(self, _event=None):
        selected = self.process_tree.selection()
        candidate = next((c for c in self.candidates if selected and f'{c.pid}:{c.start_time}' == selected[0]), None)
        if candidate is None: return
        from game_picker import candidate_details, candidate_warning
        self.process_details.set(candidate_details(candidate))
        self.process_warning.set(candidate_warning(candidate))
        self.add_process_button.state(['disabled'] if self.helper or self.client or self.busy else ['!disabled'])

    def add_selected_process(self):
        selected = self.process_tree.selection()
        candidate = next((c for c in self.candidates if selected and f'{c.pid}:{c.start_time}' == selected[0]), None)
        if candidate is None: return
        editor = self.games()
        if editor is not None:
            dialog = editor.open_running()
            if dialog is not None: dialog.query.set(candidate.name)

    def set_diagnostics_text(self, value):
        self.diagnostics_text.configure(state='normal')
        self.diagnostics_text.delete('1.0', 'end')
        self.diagnostics_text.insert('1.0', redact(value))
        self.diagnostics_text.configure(state='disabled')

    def refresh_diagnostics(self):
        self.diagnostics_button.state(['disabled'])
        def done(value, error):
            self.diagnostics_button.state(['!disabled'])
            self.set_diagnostics_text(str(error) if error else value)
        if not self._submit('diagnostics', lambda: diagnostics_snapshot(self.state), done):
            self.diagnostics_button.state(['!disabled'])

    def copy_diagnostics(self):
        value = redact(self.diagnostics_text.get('1.0', 'end-1c'))
        try:
            self.window.clipboard_clear(); self.window.clipboard_append(value)
            self.message.set('Диагностика с маскировкой скопирована.')
        except tk.TclError as error:
            self._error(error)

    def toggle_session(self):
        if self.helper or self.client: self.stop_routing()
        else: self.launch()

    def _sync_controls(self):
        if not hasattr(self, 'launch_button'): return
        running = bool(self.helper or self.client)
        stopping = getattr(self, '_stopping', False)
        self.launch_button.configure(text='Остановка…' if stopping else 'Остановить' if running else 'Подключить')
        self.launch_button.state(['disabled'] if self.busy or stopping else ['!disabled'])
        self.manage_button.state(['disabled'] if self.busy or running or stopping else ['!disabled'])
        ready = not self.busy and not running and not stopping and getattr(self, '_setup_ready', False) and bool(self.mapping_rows)
        self.udp_toggle.state(['!disabled'] if ready else ['disabled'])
        self.transport_status.set('TCP + UDP (экспериментально)' if self.udp_enabled.get() else 'TCP')
        view = session_view(helper_running=bool(self.helper), client_running=bool(self.client),
                            starting=bool(self.helper and not self.client), stopping=stopping,
                            backend_ready=getattr(self, '_backend_ready', False), error=getattr(self, '_last_error', ''))
        self.session_status.set(view.state); self.relay_status.set(view.route)
        if hasattr(self, 'backend_status'): self.backend_status.set(view.backend)
        if hasattr(self, 'client_status'): self.client_status.set(view.client)
        if hasattr(self, 'choose'): self.choose.state(['disabled'] if self.busy or running or stopping else ['!disabled'])
        if hasattr(self, 'add_process_button') and (running or self.busy or stopping): self.add_process_button.state(['disabled'])
        if hasattr(self, 'statistics'):
            age = 'Нет снимка' if self._scan_time is None else f'{int(time.monotonic() - self._scan_time)} с назад'
            duration = f'{max(0, int(time.time() - self.started))} с' if self.started and running else 'Не активна'
            sockets = len({inode for c in self.candidates for inode in c.inodes}) if self._scan_time is not None else 'Нет снимка'
            self.statistics.set(f'Сессия: {duration}  ·  Режим: {self.transport_status.get()}\nСохранено привязок: {len(self.mapping_rows)}  ·  Снимок процессов: {age}\nСокетов в снимке: {sockets}\nМаршрут: {view.route}')

    def _helper_command(self):
        command = ['pkexec', '/usr/bin/python3', '-I', str(ROOT / 'installers/linux/run_root.py'), '--uid', str(os.getuid()), '--parent', str(os.getpid()), '--map', str(self.state / 'games.map'), '--lease', str(self.state / 'desktop.lease')]
        option = getattr(self, 'udp_enabled', None)
        if option is not None and option.get(): command.append('--udp')
        return command

    def stop_routing(self):
        if self.busy: return
        self.request_stop()
        self.message.set('Остановка сессии. Для следующего теста переподключите игру.')
        self.window.deiconify()

    def configured(self):
        try:
            return State(self.state).load().get('complete') and find_client(self.state / 'prefix') is not None
        except (OSError, ValueError):
            return False

    def install(self):
        if self.busy or self.client or self.helper or self._stopping:
            return
        selected = filedialog.askopenfilename(title='Official ExitLag Windows installer', filetypes=[('Windows executable', '*.exe')])
        if not selected:
            return
        self.busy = True; self._last_error = ''; self._sync_controls()
        def work():
            try:
                Setup(self.state, ROOT / 'installers/payloads', emit=lambda stage, message: self.events.put(message)).run(Path(selected))
            except Exception as error:
                self.events.put(('error', 'Подготовка остановлена: ' + str(error)))
            finally:
                self.events.put(None)
        threading.Thread(target=work, daemon=True).start()

    def games(self):
        if self.busy or self.helper or self.client or getattr(self, '_stopping', False):
            return
        try:
            State(self.state, create=True)
        except (OSError, ValueError) as error:
            messagebox.showerror('Каталог настроек', redact(str(error))); return
        sys.path.insert(0, str(Path(__file__).parent))
        from game_picker import open_editor
        try:
            editor = open_editor(self.window, self.state / 'games.map', ROOT)
            editor.window.bind('<Destroy>', lambda event: self.window.after_idle(self.refresh_game_list) if event.widget is editor.window and self.window.winfo_exists() else None, add='+')
            return editor
        except (OSError, ValueError) as error:
            messagebox.showerror('Настройки игр', redact(str(error)), parent=self.window)

    def launch(self):
        try:
            self._launch()
        except (OSError, ValueError) as error:
            self._error(error)
            if self.lock is not None: self.request_stop()

    def _launch(self):
        if self.busy or self.helper or self.client or getattr(self, '_stopping', False):
            return
        if not self._setup_ready:
            self.message.set('Сначала подготовьте официальный клиент в настройках.'); self.show_page('setup'); return
        if not (self.state / 'games.map').is_file():
            self.message.set('Сначала добавьте игру и сохраните привязку.'); self.games(); return
        self.lock = os.open(self.state / 'desktop.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.lock); self.lock = None
            self.message.set('Сессия ExitLag Bridge уже запущена.'); return
        private_json(self.state / 'desktop-session.json', dict(pid=os.getpid(), start=starttime(os.getpid())))
        leasefd = os.open(self.state / 'desktop.lease', os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(leasefd, 'w') as output: output.write('run\n')
        self.started = time.time()
        self._last_error = ''; self._backend_ready = self._stop_failed = False
        self._session_generation += 1
        try:
            self.helper = subprocess.Popen(self._helper_command(), stdin=subprocess.DEVNULL)
        except OSError as error:
            self._error(error); self.request_stop(); return
        self.message.set('Подтвердите запуск helper в системном диалоге. Затем откроется официальный клиент.')
        self._sync_controls()

    def poll(self):
        self.tasks.poll()
        try:
            while True:
                value = self.events.get_nowait()
                if isinstance(value, tuple) and value[0] == 'client_closed' and value[1] == self._session_generation:
                    self.message.set('Клиент ExitLag закрыт. Сессия останавливается.')
                    self.request_stop()
                elif isinstance(value, tuple) and value[0] == 'error':
                    self._error(value[1])
                elif isinstance(value, tuple) and value[0] == 'stop_complete':
                    if value[1] != self._session_generation: continue
                    _, _, warning, client_stopped, helper_stopped = value
                    if client_stopped: self.client = None
                    if helper_stopped: self.helper = None
                    self._stopping = self._backend_ready = False
                    self._stop_failed = not (client_stopped and helper_stopped)
                    if not self._stop_failed and self.lock is not None:
                        os.close(self.lock); self.lock = None
                    if warning: self._error(warning)
                    else: self.message.set('Остановлено. Переподключите игру перед новой сессией.')
                    if self._closing and not self._stop_failed:
                        self.tasks.close(); self.window.destroy(); return
                    self._closing = False
                elif isinstance(value, tuple) and value[0] == 'client_check_done':
                    if value[1] == self._session_generation: self.checking = False
                elif value is None:
                    self.busy = False; self.refresh_setup()
                elif not isinstance(value, tuple): self.message.set(redact(str(value)))
        except queue.Empty:
            pass
        if self.helper and not self._stopping and not self._stop_failed:
            try:
                (self.state / 'desktop.lease').touch()
                if self.helper.poll() is not None:
                    self._error('Helper завершился или авторизация отменена.'); self.request_stop()
                elif not self.client:
                    token = Path('/run/exitlag-linux/ipc.token')
                    try:
                        info = token.lstat()
                        ready = stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1 and not info.st_mode & 0o077 and info.st_mtime >= self.started
                    except OSError:
                        ready = False
                    if ready:
                        self._backend_ready = True
                        client = find_client(self.state / 'prefix')
                        if client is None: raise ValueError('Не найден установленный клиент ExitLag.')
                        logfd = open_client_log(self.state / 'client.log')
                        with os.fdopen(logfd, 'ab') as log:
                            self.client = subprocess.Popen([str(self.state / 'runtime/bin/wine'), str(client)], cwd=client.parent,
                                env=environment(self.state, token), stdin=subprocess.DEVNULL, stdout=log, stderr=log)
                        self.message.set('Клиент запущен. Выберите игру и примените маршрут в ExitLag. Маршрут не подтверждён.')
                    elif time.time() - self.started > 120:
                        self._error('Истекло время ожидания helper.'); self.request_stop()
                elif time.time() - self.started > 25 and time.time() - self.last_check > 5 and not self.checking:
                    self.last_check = time.time(); self.checking = True
                    threading.Thread(target=self.check_client, args=(self._session_generation,), daemon=True).start()
            except (OSError, ValueError) as error:
                self._error(error); self.request_stop()
        self._sync_controls()
        self.window.after(100, self.poll)

    def check_client(self, generation=None):
        if generation is None: generation = getattr(self, '_session_generation', 0)
        try:
            if client_present(self.state) is False: self.events.put(('client_closed', generation))
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            self.events.put(('client_check_done', generation))

    def request_stop(self):
        if getattr(self, '_stopping', False): return
        try:
            (self.state / 'desktop.lease').unlink(missing_ok=True)
        except OSError as error:
            self._error(error); return
        self._stopping = True
        self._stop_failed = False
        self._session_generation = getattr(self, '_session_generation', 0) + 1
        generation = self._session_generation
        self.checking = False
        client, helper = self.client, self.helper
        def work():
            warning = ''
            client_stopped, helper_stopped = not bool(client), not bool(helper)
            try:
                if client:
                    warning = stop_client(self.state)
                    client_stopped = not bool(warning)
            except (OSError, subprocess.TimeoutExpired):
                warning = 'Не удалось подтвердить закрытие ExitLag. Проверьте окно клиента.'
            try:
                if helper:
                    helper.wait(timeout=10)
                    helper_stopped = True
            except (OSError, subprocess.TimeoutExpired):
                warning += ' Завершение supervisor не подтверждено; проверьте диагностику.'
            self.events.put(('stop_complete', generation, warning, client_stopped, helper_stopped))
        threading.Thread(target=work, daemon=True).start()
        self._sync_controls()

    def stop_session(self):
        # Compatibility entry for callers; the actual UI never waits for Wine.
        self.request_stop()

    def close(self):
        if self.busy:
            messagebox.showinfo('Подготовка клиента', 'Завершите или отмените установку перед выходом.'); return
        self._closing = True
        if self.helper or self.client or self._stopping:
            self.request_stop()
        else:
            if hasattr(self, 'tasks'): self.tasks.close()
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
