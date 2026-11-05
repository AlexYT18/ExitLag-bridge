"""Unprivileged game selection and private mapping editor.
SPDX-License-Identifier: GPL-3.0-only
"""
import importlib.util
import os
from pathlib import Path, PureWindowsPath
import queue
import re
import secrets
import stat
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

# Also support direct importlib-based desktop/test entry points.
_support_spec = importlib.util.spec_from_file_location(
    '_exitlag_picker_support', Path(__file__).with_name('desktop_support.py'))
_support = importlib.util.module_from_spec(_support_spec)
_support_spec.loader.exec_module(_support)
redact = _support.redact

MAX_MAP = 65536
_TECHNICAL = re.compile(r'^(wineserver|steam|steamwebhelper|opencode|discord|chrome|firefox|systemd|dbus|pipewire|wireplumber|plasmashell|xwayland)(?:$|[.\-])', re.I)


def display_path(value):
    """Presentation only: never change the path used for identity verification."""
    if not value:
        return '—'
    value = str(value)
    name = PureWindowsPath(value).name if '\\' in value else Path(value).name
    name = ''.join(c for c in name if ord(c) >= 32 and ord(c) != 127)
    return '…/' + name if name else '…'


def candidate_warning(item, image_count=None):
    """Informational classification, never a substitute for owner verification."""
    names = (item.name.casefold(), item.executable.name.casefold())
    if any(name.startswith('wineserver') for name in names):
        return 'Выбран wineserver — это общий сервис Wine, а не подтверждённый процесс игры. Выберите процесс, владеющий сокетами игры.'
    if any(re.search(r'(^steam(?:[.\-]|$)|steamwebhelper|launcher)', name) for name in names):
        return 'Похоже на launcher или Steam. Его соединения не подтверждают трафик самой игры; проверьте владельца игровых сокетов.'
    if image_count is not None and image_count > 1:
        return 'Найдено несколько Windows images: выберите реальный executable игры. Автоматическая привязка неоднозначна.'
    if item.prefix and image_count == 0:
        return 'Windows image не найден: требуется настоящий executable или подтверждённая identity. Путь не будет угадан.'
    return ''


def candidate_details(item):
    suffix = f' · Steam AppID {item.steam_appid}' if item.steam_appid else ''
    name = redact(item.name).replace('\n', ' ')
    return (f'{name} · PID {item.pid} · {item.kind.title()}{suffix}\n'
            f'Executable: {display_path(item.executable)}\n'
            f'Wine / Proton prefix: {display_path(item.prefix)}')


def _private(info, uid):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or
            info.st_nlink != 1 or info.st_mode & 0o077 or info.st_size > MAX_MAP):
        raise ValueError('Game settings must be a private regular file owned by you')


def load_map(path, uid=None):
    uid = os.getuid() if uid is None else uid
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except FileNotFoundError:
        return ''
    try:
        _private(os.fstat(fd), uid)
        data = os.read(fd, MAX_MAP + 1)
        if len(data) > MAX_MAP:
            raise ValueError('Game settings are too large')
        return data.decode('utf-8')
    finally:
        os.close(fd)


def save_map(path, text, validator, uid=None, expected=None):
    """Validate the exact private temporary file and atomically replace settings."""
    uid = os.getuid() if uid is None else uid
    path = Path(path)
    encoded = text.encode('utf-8')
    if len(encoded) > MAX_MAP:
        raise ValueError('Game settings are too large')
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = '.games-' + secrets.token_hex(16) + '.map'
    try:
        parent = os.fstat(directory)
        if parent.st_uid != uid or parent.st_mode & 0o022:
            raise ValueError('Game settings directory must be owned by you and not writable by others')
        anchored = Path('/proc/self/fd') / str(directory)
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            previous = ''
        else:
            _private(info, uid)
            previous = load_map(anchored / path.name, uid)
        if expected is not None and previous != expected:
            raise ValueError('Game settings changed elsewhere; reopen this window before saving')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        validator(anchored / temporary, uid)
        # Check again after validation, which may inspect paths on slow filesystems.
        if load_map(anchored / path.name, uid) != previous:
            raise ValueError('Game settings changed during validation; reopen this window')
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


class MappingController:
    """Keep comments and advanced/legacy rows intact while managing normal rows."""
    def __init__(self, text=''):
        self.original = text
        self.text = text

    def rows(self):
        result = []
        for index, line in enumerate(self.text.splitlines(keepends=True)):
            value = line.rstrip('\r\n')
            if not value.strip() or value.lstrip().startswith('#'):
                continue
            fields = value.split('\t')
            prefix = fields[0].startswith('wineprefix:')
            source = fields[0].removeprefix('wineprefix:')
            identity = fields[1] if len(fields) > 1 else ''
            valid = len(fields) == (3 if prefix else 2)
            name = PureWindowsPath(identity).name or Path(source).name or 'Unconfigured entry'
            kind = ('Wine / Proton' if prefix else 'Native') if valid else 'Needs review'
            result.append((index, name, kind, identity, source))
        return result

    def add(self, row):
        values = row.rstrip('\n').split('\t')
        prefix = values[0].startswith('wineprefix:') if values else False
        if (len(values) != (3 if prefix else 2) or any(not v or any(ord(c) < 32 or ord(c) == 127 for c in v) for v in values)):
            raise ValueError('The selected process did not produce a valid game entry')
        key = (values[0], values[2] if prefix else None)
        for line in self.text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            fields = line.split('\t')
            existing = (fields[0], fields[2] if len(fields) == 3 else None)
            if existing == key:
                raise ValueError('This executable and prefix are already configured; edit the existing entry in Advanced')
        self.text += ('\n' if self.text and not self.text.endswith('\n') else '') + '\t'.join(values) + '\n'

    def remove(self, indices):
        indices = set(indices)
        self.text = ''.join(line for index, line in enumerate(self.text.splitlines(keepends=True)) if index not in indices)

    def replace(self, index, row):
        """Validate a replacement without changing other lines or a failed draft."""
        lines = self.text.splitlines(keepends=True)
        if (isinstance(index, bool) or not isinstance(index, int) or
                index < 0 or index >= len(lines) or not lines[index].strip() or
                lines[index].lstrip().startswith('#')):
            raise ValueError('Select one existing game entry')
        trial = MappingController(''.join(line for number, line in enumerate(lines) if number != index))
        trial.add(row)
        ending = '\r\n' if lines[index].endswith('\r\n') else '\n' if lines[index].endswith('\n') else ''
        lines[index] = row.rstrip('\n') + ending
        replacement = ''.join(lines)
        if len(replacement.encode('utf-8')) > MAX_MAP:
            raise ValueError('Game settings are too large')
        self.text = replacement

    def advanced(self, text):
        if len(text.encode('utf-8')) > MAX_MAP:
            raise ValueError('Game settings are too large')
        self.text = text


def visible_candidates(candidates, query='', show_all=False, sort_by=None, descending=False):
    query = query.casefold().strip()
    result = []
    for item in candidates:
        if not show_all and (_TECHNICAL.search(item.name) or _TECHNICAL.search(item.executable.name)):
            continue
        searchable = f'{item.name} {item.pid} {item.kind} {item.steam_appid or ""}'.casefold()
        if not query or query in searchable:
            result.append(item)
    keys = {
        'name': lambda item: (item.name.casefold(), item.pid),
        'pid': lambda item: item.pid,
        'runtime': lambda item: (item.kind.casefold(), item.name.casefold(), item.pid),
        'transport': lambda item: (tuple(item.transports), item.pid),
        'sockets': lambda item: (item.socket_count, item.pid),
        'appid': lambda item: (not bool(item.steam_appid), int(item.steam_appid or 0), item.pid),
    }
    if sort_by is not None:
        return sorted(result, key=keys[sort_by], reverse=descending)
    return sorted(result, key=lambda item: (not item.name.lower().endswith('.exe'), item.name.casefold(), item.pid))


def manual_mapping(parent, prefix=False):
    """Preserve explicit offline configuration under the advanced editor."""
    source = (filedialog.askdirectory(parent=parent, title='Game Wine prefix') if prefix else
              filedialog.askopenfilename(parent=parent, title='Native game executable'))
    if not source:
        return None
    owner = None
    if prefix:
        owner = filedialog.askopenfilename(parent=parent, title='Actual Wine/Proton socket-owner executable')
        if not owner:
            return None
    identity = simpledialog.askstring('Confirmed Windows identity', 'Full Windows executable identity confirmed for this game in ExitLag:', parent=parent)
    if identity is None:
        return None
    fields = [('wineprefix:' if prefix else '') + str(Path(source).resolve(strict=True)), identity]
    if owner:
        fields.append(str(Path(owner).resolve(strict=True)))
    row = '\t'.join(fields)
    # Reject control characters before putting the row in the editable draft.
    trial = MappingController(); trial.add(row)
    return trial.text


class TaskQueue:
    """Workers only publish data; all callbacks are delivered on the UI thread."""
    def __init__(self):
        self.owner = threading.get_ident()
        self.results = queue.Queue()
        self.serial = 0
        self.latest = {}
        self.active = set()
        self.closed = False

    def _owner(self):
        if threading.get_ident() != self.owner:
            raise RuntimeError('UI task callbacks must run on the creating thread')

    def submit(self, kind, operation, callback):
        self._owner()
        if self.closed:
            raise RuntimeError('This window is closed')
        if len(self.active) >= 4:
            raise ValueError('Previous checks are still running; wait a moment')
        self.serial += 1
        token = self.serial
        self.latest[kind] = token
        self.active.add(token)
        def work():
            try:
                value, error = operation(), None
            except Exception as failure:
                value, error = None, failure
            self.results.put((kind, token, value, error, callback))
        threading.Thread(target=work, daemon=True).start()
        return token

    def cancel(self, kind):
        self._owner()
        self.latest.pop(kind, None)

    def poll(self):
        self._owner()
        while True:
            try:
                kind, token, value, error, callback = self.results.get_nowait()
            except queue.Empty:
                break
            self.active.discard(token)
            if not self.closed and self.latest.get(kind) == token:
                callback(value, error)

    def close(self):
        self._owner()
        self.closed = True
        self.latest.clear()


class RunningGameDialog:
    def __init__(self, parent, picker, on_add):
        self.picker, self.on_add = picker, on_add
        self.window = tk.Toplevel(parent)
        self.window.title('Choose a running game')
        self.window.geometry('1000x700')
        self.window.minsize(900, 640)
        self.window.transient(parent)
        self.tasks = TaskQueue()
        self.closed = False
        self.candidates, self.images = [], []
        self.selected = self.manual_identity = None
        self.sort_by, self.descending = None, False
        self.query, self.show_all = tk.StringVar(), tk.BooleanVar(value=False)
        self.status, self.details = tk.StringVar(value='Reading your network processes...'), tk.StringVar()
        self.selection_warning = tk.StringVar()
        body = ttk.Frame(self.window, padding=16)
        body.pack(fill='both', expand=True)
        bottom = ttk.Frame(body); bottom.pack(side='bottom', fill='x', pady=(10, 0))
        ttk.Label(body, text='Start the game and open a network session, then select it below.').pack(anchor='w')
        controls = ttk.Frame(body)
        controls.pack(fill='x', pady=10)
        ttk.Label(controls, text='Search').pack(side='left')
        self.search_entry = ttk.Entry(controls, textvariable=self.query)
        self.search_entry.pack(side='left', fill='x', expand=True, padx=8)
        self.clear_button = ttk.Button(controls, text='Clear', command=self.clear_search)
        self.clear_button.pack(side='left', padx=(0, 8))
        self.refresh_button = ttk.Button(controls, text='Refresh', command=self.refresh)
        self.refresh_button.pack(side='left')
        ttk.Checkbutton(body, text='Show all network processes', variable=self.show_all, command=self.render).pack(anchor='w')
        columns = ('name', 'pid', 'runtime', 'transport', 'sockets', 'appid')
        frame = ttk.Frame(body); frame.pack(fill='both', expand=True, pady=8)
        self.process_tree = ttk.Treeview(frame, columns=columns, show='headings', selectmode='browse', height=7)
        for name, title, width in zip(columns, ('Game / process', 'PID', 'Runtime', 'Transport', 'Sockets', 'Steam AppID'), (260, 70, 105, 100, 70, 100)):
            self.process_tree.heading(name, text=title, command=lambda column=name: self.sort(column))
            self.process_tree.column(name, width=width, minwidth=55)
        self.column_titles = dict(zip(columns, ('Game / process', 'PID', 'Runtime', 'Transport', 'Sockets', 'Steam AppID')))
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=scrollbar.set)
        self.process_tree.pack(side='left', fill='both', expand=True); scrollbar.pack(side='right', fill='y')
        self.process_tree.bind('<<TreeviewSelect>>', self.select)
        ttk.Label(body, textvariable=self.details, wraplength=920).pack(anchor='w', pady=(2, 8))
        ttk.Label(body, textvariable=self.selection_warning, wraplength=920,
                  foreground='#f1bd68').pack(anchor='w', pady=(0, 6))
        image_line = ttk.Frame(body); image_line.pack(fill='x')
        ttk.Label(image_line, text='Windows game image').pack(side='left')
        self.image_combo = ttk.Combobox(image_line, state='readonly')
        self.image_combo.pack(side='left', fill='x', expand=True, padx=8)
        self.image_combo.bind('<<ComboboxSelected>>', self.image_selected)
        self.browse_button = ttk.Button(image_line, text='Choose game .exe...', command=self.choose_file, state='disabled')
        self.browse_button.pack(side='left')
        advanced = ttk.Frame(body); advanced.pack(fill='x', pady=8)
        ttk.Button(advanced, text='Advanced identity...', command=self.advanced_identity).pack(side='left')
        ttk.Label(body, text='Select the same game in official ExitLag. A file match does not verify service recognition or relay traffic.', wraplength=920).pack(anchor='w')
        self.transport_note = ttk.Label(body, text='TCP is enabled by default. Experimental UDP can be enabled in the dashboard before launching; listed sockets do not verify routing.', wraplength=920)
        self.transport_note.pack(anchor='w', pady=(4, 8))
        ttk.Label(body, textvariable=self.status, wraplength=920).pack(anchor='w')
        self.add_button = ttk.Button(bottom, text='Add selected game', command=self.add, state='disabled')
        self.add_button.pack(side='right'); ttk.Button(bottom, text='Cancel', command=self.close).pack(side='right', padx=8)
        self.query.trace_add('write', lambda *_: self.render())
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        self.window.bind('<Destroy>', self._destroyed)
        self.window.bind('<Control-f>', self.focus_search)
        self.window.bind('<F5>', self.refresh_key)
        self.search_entry.bind('<Down>', self.focus_processes)
        self.window.grab_set()
        self.search_entry.focus_set()
        self.timer = self.window.after(50, self.poll)
        self.refresh()

    def _destroyed(self, event):
        if event.widget is self.window and not self.closed:
            self.closed = True; self.tasks.close()

    def poll(self):
        if self.closed: return
        self.tasks.poll()
        if not self.closed:
            self.timer = self.window.after(50, self.poll)

    def _submit(self, kind, operation, callback):
        try:
            self.tasks.submit(kind, operation, callback)
            return True
        except (ValueError, RuntimeError) as error:
            self.status.set(redact(error))
            return False

    def focus_search(self, _event=None):
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, 'end')
        return 'break'

    def clear_search(self):
        self.query.set('')
        self.focus_search()

    def focus_processes(self, _event=None):
        entries = self.process_tree.get_children()
        if entries:
            self.process_tree.focus_set()
            selected = self.process_tree.selection()
            entry = selected[0] if selected else entries[0]
            self.process_tree.selection_set(entry)
            self.process_tree.focus(entry)
            self.process_tree.see(entry)
        return 'break'

    def refresh_key(self, _event=None):
        if not self.refresh_button.instate(['disabled']):
            self.refresh()
        return 'break'

    def sort(self, column):
        self.descending = not self.descending if self.sort_by == column else False
        self.sort_by = column
        for name, title in self.column_titles.items():
            suffix = (' ▼' if self.descending else ' ▲') if name == column else ''
            self.process_tree.heading(name, text=title + suffix)
        self.render()

    def refresh(self):
        self.selected = self.manual_identity = None
        self.process_tree.delete(*self.process_tree.get_children())
        self.details.set('')
        self.selection_warning.set('')
        self.images = []; self.image_combo.configure(values=()); self.image_combo.set('')
        self.add_button.state(['disabled']); self.browse_button.state(['disabled'])
        self.tasks.cancel('images'); self.tasks.cancel('file'); self.tasks.cancel('mapping')
        self.status.set('Reading your network processes...'); self.refresh_button.state(['disabled'])
        def done(items, error):
            self.refresh_button.state(['!disabled'])
            if error:
                self.candidates = []; self.render(); self.status.set(redact(error))
            else:
                self.candidates = items; self.render()
        if not self._submit('scan', self.picker.list_candidates, done):
            self.refresh_button.state(['!disabled'])

    def render(self):
        items = visible_candidates(self.candidates, self.query.get(), self.show_all.get(),
                                   self.sort_by, self.descending)
        visible_ids = {f'{item.pid}:{item.start_time}' for item in items}
        for entry in self.process_tree.get_children():
            if entry not in visible_ids:
                self.process_tree.delete(entry)
        for position, item in enumerate(items):
            iid = f'{item.pid}:{item.start_time}'
            values = (item.name, item.pid, item.kind.title(), '/'.join(p.upper() for p in item.transports), item.socket_count, item.steam_appid or '-')
            if self.process_tree.exists(iid):
                self.process_tree.item(iid, values=values)
                self.process_tree.move(iid, '', position)
            else:
                self.process_tree.insert('', position, iid=iid, values=values)
        if self.selected is not None and f'{self.selected.pid}:{self.selected.start_time}' not in visible_ids:
            self.selected = self.manual_identity = None; self.images = []
            self.tasks.cancel('images'); self.tasks.cancel('file'); self.tasks.cancel('mapping')
            self.image_combo.configure(values=()); self.image_combo.set('')
            self.add_button.state(['disabled']); self.browse_button.state(['disabled'])
            self.details.set('')
            self.selection_warning.set('')
        visible = len(items)
        self.status.set(f'{visible} process(es) shown. Select a game.' if visible else 'No matching game found. Open a game session, Refresh, or Show all network processes.')

    def select(self, _event=None):
        selection = self.process_tree.selection()
        if not selection: return
        item = next((c for c in self.candidates if f'{c.pid}:{c.start_time}' == selection[0]), None)
        if item is None or item == self.selected: return
        self.selected, self.manual_identity, self.images = item, None, []
        self.tasks.cancel('images'); self.tasks.cancel('file'); self.tasks.cancel('mapping')
        self.image_combo.configure(values=()); self.image_combo.set(''); self.add_button.state(['disabled'])
        self.browse_button.state(['!disabled'] if item.prefix else ['disabled'])
        scope = 'This rule permits the selected runtime in this game prefix, including other programs launched in that prefix.' if item.prefix else 'Native Linux game: choose Advanced identity to enter its confirmed ExitLag Windows identity.'
        self.details.set(candidate_details(item))
        self.selection_warning.set(candidate_warning(item) or scope)
        self.status.set('Checking Windows images mapped by this process...')
        def done(images, error):
            if self.selected != item: return
            if error: self.status.set(redact(error)); return
            self.images = images
            self.selection_warning.set(candidate_warning(item, len(images)) or scope)
            self.image_combo.configure(values=[image.path.name for image in images])
            if len(images) == 1:
                self.image_combo.current(0); self.image_selected()
            else:
                self.status.set('Choose the game image from the list.' if images else 'No mapped game image found. Choose the actual game .exe file or use Advanced identity.')
        self._submit('images', lambda: self.picker.windows_images(item), done)

    def image_selected(self, _event=None):
        self.tasks.cancel('images'); self.tasks.cancel('file')
        self.tasks.cancel('mapping')
        self.manual_identity = None
        self.add_button.state(['!disabled'] if self.selected and self.image_combo.current() >= 0 else ['disabled'])
        if self.selected:
            self.selection_warning.set(candidate_warning(self.selected) or
                ('Привязка разрешает выбранный runtime во всём prefix.' if self.selected.prefix else
                 'Windows identity должна быть подтверждена для этой игры в ExitLag.'))
        self.status.set('Game image selected. Ownership and image will be checked again when adding.')

    def choose_file(self):
        item = self.selected
        if item is None or item.prefix is None: return
        path = filedialog.askopenfilename(parent=self.window, title='Choose the actual Windows game executable', filetypes=[('Windows executable', '*.exe'), ('All files', '*')])
        if not path: return
        self.tasks.cancel('images'); self.tasks.cancel('mapping')
        self.add_button.state(['disabled']); self.status.set('Checking the selected game executable...')
        def done(image, error):
            if self.selected != item: return
            if error: self.status.set(redact(error)); return
            self.images = [image]; self.manual_identity = None
            self.image_combo.configure(values=[image.path.name])
            self.image_combo.current(0); self.image_selected()
        self._submit('file', lambda: self.picker.image_from_file(item, path), done)

    def advanced_identity(self):
        if self.selected is None: return
        identity = simpledialog.askstring('Confirmed Windows identity', 'Enter the full Windows executable identity you have confirmed for this game in ExitLag.', parent=self.window)
        if identity is None: return
        self.tasks.cancel('images'); self.tasks.cancel('file'); self.tasks.cancel('mapping')
        self.manual_identity = identity; self.image_combo.set('Explicit identity (advanced)')
        self.add_button.state(['!disabled']); self.status.set('Explicit identity selected; it will be validated before adding.')

    def add(self):
        item = self.selected
        index = self.image_combo.current()
        image = self.images[index] if 0 <= index < len(self.images) and self.manual_identity is None else None
        identity = self.manual_identity
        if item is None or (image is None and identity is None): return
        self.add_button.state(['disabled']); self.status.set('Rechecking the process and socket owner...')
        def done(row, error):
            if self.selected != item: return
            if error: self.status.set(redact(error)); return
            try: self.on_add(row)
            except (OSError, ValueError) as failure:
                self.status.set(redact(failure)); return
            self.close()
        self._submit('mapping', lambda: self.picker.mapping(item, image=image, windows_identity=identity), done)

    def close(self):
        if self.closed: return
        self.closed = True; self.tasks.close()
        try: self.window.after_cancel(self.timer)
        except tk.TclError: pass
        parent = self.window.master
        self.window.destroy()
        try:
            if parent.winfo_exists(): parent.grab_set()
        except tk.TclError: pass


class MappingEditor:
    def __init__(self, parent, path, root, picker=None, validator=None):
        self.path, self.root = Path(path), Path(root)
        if validator is None:
            spec = importlib.util.spec_from_file_location('_exitlag_picker_validator', Path(__file__).with_name('run_root.py'))
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            validator = module.read_map
        self.validator = validator
        self.controller = MappingController(load_map(self.path))
        if picker is None:
            from bridge_setup.process_picker import ProcessPicker
            picker = ProcessPicker(self.root / 'tools/discover-game-processes.py')
        self.picker = picker
        self.running_dialog = None
        self.tasks, self.closed, self.saving = TaskQueue(), False, False
        self.window = tk.Toplevel(parent)
        self.window.title('Configured games'); self.window.geometry('900x480'); self.window.minsize(720, 400)
        self.window.transient(parent)
        body = ttk.Frame(self.window, padding=16); body.pack(fill='both', expand=True)
        ttk.Label(body, text='Add a running game to capture its executable and Proton/Wine prefix automatically.').pack(anchor='w')
        frame = ttk.Frame(body); frame.pack(fill='both', expand=True, pady=12)
        self.tree = ttk.Treeview(frame, columns=('name', 'kind', 'identity'), show='headings', selectmode='extended')
        for name, title, width in (('name', 'Game', 190), ('kind', 'Environment', 130), ('identity', 'Windows image', 490)):
            self.tree.heading(name, text=title); self.tree.column(name, width=width, minwidth=80)
        scrollbar = ttk.Scrollbar(frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side='left', fill='both', expand=True); scrollbar.pack(side='right', fill='y')
        controls = ttk.Frame(body); controls.pack(fill='x')
        self.add_button = ttk.Button(controls, text='Add running game...', command=self.open_running); self.add_button.pack(side='left')
        self.edit_button = ttk.Button(controls, text='Изменить', command=self.edit_selected); self.edit_button.pack(side='left', padx=(8, 0))
        self.remove_button = ttk.Button(controls, text='Remove', command=self.remove); self.remove_button.pack(side='left', padx=8)
        self.advanced_button = ttk.Button(controls, text='Advanced...', command=self.advanced); self.advanced_button.pack(side='left')
        self.save_button = ttk.Button(controls, text='Save', command=self.save); self.save_button.pack(side='right')
        ttk.Button(controls, text='Cancel', command=self.close).pack(side='right', padx=8)
        self.status = tk.StringVar(value='Select the same game in official ExitLag before testing a new connection.')
        ttk.Label(body, textvariable=self.status, wraplength=840).pack(anchor='w', pady=(12, 0))
        self.window.protocol('WM_DELETE_WINDOW', self.close)
        self.window.bind('<Destroy>', self._destroyed)
        self.window.grab_set(); self.timer = self.window.after(50, self.poll)
        self.render()

    def _destroyed(self, event):
        if event.widget is self.window and not self.closed:
            self.closed = True; self.tasks.close()

    def poll(self):
        if self.closed: return
        self.tasks.poll()
        if not self.closed:
            self.timer = self.window.after(50, self.poll)

    def render(self):
        self.tree.delete(*self.tree.get_children())
        for index, name, kind, identity, _source in self.controller.rows():
            self.tree.insert('', 'end', iid=str(index), values=(name, kind, display_path(identity)))

    def open_running(self):
        if self.saving: return None
        try:
            self.running_dialog = RunningGameDialog(self.window, self.picker, self.add_row)
            return self.running_dialog
        except (OSError, ValueError) as error:
            messagebox.showerror('Game selection', redact(error), parent=self.window)

    def add_row(self, row):
        self.controller.add(row); self.render(); self.status.set('Game added. Save to use it next time routing starts.')

    def remove(self):
        if self.saving: return
        self.controller.remove(int(value) for value in self.tree.selection()); self.render()

    def edit_selected(self):
        if self.saving: return None
        selected = self.tree.selection()
        if len(selected) != 1:
            self.status.set('Выберите одну игру для редактирования.'); return None
        index = int(selected[0])
        fields = self.controller.text.splitlines()[index].split('\t')
        prefix = fields[0].startswith('wineprefix:')
        if len(fields) != (3 if prefix else 2):
            self.status.set('Эта запись требует проверки в Advanced. Исходная строка сохранена.'); return None
        dialog = tk.Toplevel(self.window)
        dialog.title('Изменить игру'); dialog.geometry('680x360')
        dialog.transient(self.window); dialog.grab_set()
        body = ttk.Frame(dialog, padding=20); body.pack(fill='both', expand=True)
        ttk.Label(body, text='Редактирование выбранной привязки', font=('', 14, 'bold')).pack(anchor='w')
        summary = tk.StringVar()
        def describe():
            source = fields[0].removeprefix('wineprefix:')
            summary.set(f'Windows identity: {display_path(fields[1])}\n'
                        f'{"Prefix" if prefix else "Executable"}: {display_path(source)}' +
                        (f'\nRuntime: {display_path(fields[2])}' if prefix else ''))
        describe()
        ttk.Label(body, textvariable=summary, wraplength=620).pack(anchor='w', pady=(14, 12))
        ttk.Label(body, text='Полные пути скрыты. Изменения остаются черновиком до Save; при сохранении повторно проверяются executable, prefix и права файла.', wraplength=620).pack(anchor='w')
        controls = ttk.Frame(body); controls.pack(fill='x', pady=16)
        def identity():
            value = simpledialog.askstring('Windows identity', 'Полная Windows identity, подтверждённая для этой игры в ExitLag:', parent=dialog)
            if value is not None:
                fields[1] = value; describe()
        def source():
            value = (filedialog.askdirectory(parent=dialog, title='Выберите игровой prefix') if prefix else
                     filedialog.askopenfilename(parent=dialog, title='Выберите executable игры'))
            if value:
                try: fields[0] = ('wineprefix:' if prefix else '') + str(Path(value).resolve(strict=True))
                except OSError as error:
                    messagebox.showerror('Executable / prefix', type(error).__name__, parent=dialog); return
                describe()
        def owner():
            value = filedialog.askopenfilename(parent=dialog, title='Выберите runtime, владеющий сокетами игры')
            if value:
                try: fields[2] = str(Path(value).resolve(strict=True))
                except OSError as error:
                    messagebox.showerror('Runtime', type(error).__name__, parent=dialog); return
                describe()
        ttk.Button(controls, text='Windows identity…', command=identity).pack(side='left')
        ttk.Button(controls, text='Выбрать prefix…' if prefix else 'Выбрать executable…', command=source).pack(side='left', padx=8)
        if prefix: ttk.Button(controls, text='Выбрать runtime…', command=owner).pack(side='left')
        def cancel():
            dialog.destroy(); self.window.grab_set()
        def apply():
            try: self.controller.replace(index, '\t'.join(fields))
            except ValueError as error:
                messagebox.showerror('Изменить игру', redact(error), parent=dialog); return
            self.render(); self.tree.selection_set(str(index))
            self.status.set('Игра изменена. Нажмите Save для проверки и сохранения настроек.')
            cancel()
        actions = ttk.Frame(body); actions.pack(fill='x', side='bottom')
        ttk.Button(actions, text='Применить', command=apply).pack(side='right')
        ttk.Button(actions, text='Отмена', command=cancel).pack(side='right', padx=8)
        dialog.protocol('WM_DELETE_WINDOW', cancel)
        return dialog

    def advanced(self):
        if self.saving: return
        dialog = tk.Toplevel(self.window); dialog.title('Advanced mappings'); dialog.geometry('900x460')
        dialog.transient(self.window); dialog.grab_set()
        ttk.Label(dialog, text='Manual mappings use Tabs. Wine/Proton rows require prefix, Windows identity, and actual runtime executable. Existing rows and comments are preserved.', wraplength=850).pack(padx=16, pady=10, anchor='w')
        editor = tk.Text(dialog, wrap='none', background='#18202b', foreground='#e6edf3',
                         insertbackground='#e6edf3', selectbackground='#315d80', relief='flat')
        editor.pack(fill='both', expand=True, padx=16)
        editor.insert('1.0', self.controller.text)
        def cancel():
            dialog.destroy(); self.window.grab_set()
        def apply():
            try: self.controller.advanced(editor.get('1.0', 'end-1c'))
            except ValueError as error:
                messagebox.showerror('Advanced mappings', redact(error), parent=dialog); return
            self.render(); cancel()
        def insert(prefix=False):
            try:
                row = manual_mapping(dialog, prefix)
                if row:
                    if editor.get('1.0', 'end-1c') and editor.get('end-2c', 'end-1c') != '\n':
                        editor.insert('end', '\n')
                    editor.insert('end', row)
            except (OSError, ValueError) as error:
                messagebox.showerror('Manual mapping', redact(error), parent=dialog)
        line = ttk.Frame(dialog); line.pack(fill='x', padx=16, pady=12)
        ttk.Button(line, text='Add executable...', command=insert).pack(side='left')
        ttk.Button(line, text='Add Wine prefix...', command=lambda: insert(True)).pack(side='left', padx=8)
        ttk.Button(line, text='Apply edits', command=apply).pack(side='right')
        ttk.Button(line, text='Cancel', command=cancel).pack(side='right', padx=8)
        dialog.protocol('WM_DELETE_WINDOW', cancel)

    def save(self):
        if self.saving: return
        self.saving = True; self.status.set('Validating and saving game settings...')
        self.save_button.state(['disabled']); self.add_button.state(['disabled']); self.remove_button.state(['disabled']); self.edit_button.state(['disabled']); self.advanced_button.state(['disabled'])
        text, original = self.controller.text, self.controller.original
        def done(_value, error):
            self.saving = False
            if error:
                self.status.set(redact(error))
                self.save_button.state(['!disabled']); self.add_button.state(['!disabled']); self.remove_button.state(['!disabled']); self.edit_button.state(['!disabled']); self.advanced_button.state(['!disabled'])
            else:
                self.controller.original = text; self.close()
        self.tasks.submit('save', lambda: save_map(self.path, text, self.validator, expected=original), done)

    def close(self):
        if self.closed or self.saving: return
        self.closed = True; self.tasks.close()
        try: self.window.after_cancel(self.timer)
        except tk.TclError: pass
        if self.running_dialog is not None: self.running_dialog.close()
        self.window.destroy()


def open_editor(parent, path, root):
    return MappingEditor(parent, path, root)
