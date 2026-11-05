"""Tk/ttk presentation for the Linux desktop; no routing or process authority.
SPDX-License-Identifier: GPL-3.0-only
"""
import tkinter as tk
from tkinter import ttk

COLORS = dict(bg='#101319', sidebar='#151922', panel='#1b202b', field='#242c39',
              text='#edf0f7', muted='#a5afbf', accent='#ee5367', border='#303949')


def theme(window):
    c = COLORS
    window.configure(background=c['bg'])
    window.option_add('*Background', c['panel'])
    window.option_add('*Foreground', c['text'])
    window.option_add('*insertBackground', c['text'])
    style = ttk.Style(window)
    style.theme_use('clam')
    style.configure('.', background=c['bg'], foreground=c['text'], font=('DejaVu Sans', 10), bordercolor=c['border'])
    style.configure('TFrame', background=c['bg'])
    style.configure('Card.TFrame', background=c['panel'])
    style.configure('Sidebar.TFrame', background=c['sidebar'])
    style.configure('TLabel', background=c['bg'], foreground=c['text'])
    style.configure('Card.TLabel', background=c['panel'])
    style.configure('Muted.TLabel', foreground=c['muted'])
    style.configure('CardMuted.TLabel', background=c['panel'], foreground=c['muted'])
    style.configure('Title.TLabel', font=('DejaVu Sans', 21, 'bold'))
    style.configure('Heading.TLabel', font=('DejaVu Sans', 12, 'bold'))
    style.configure('CardHeading.TLabel', background=c['panel'], font=('DejaVu Sans', 13, 'bold'))
    style.configure('TButton', padding=(12, 8), background=c['field'], borderwidth=0, focusthickness=2)
    style.map('TButton', background=[('active', '#354156'), ('disabled', c['panel'])], foreground=[('disabled', '#697589')])
    style.configure('Accent.TButton', background=c['accent'], foreground='white', font=('DejaVu Sans', 11, 'bold'), padding=(22, 12))
    style.map('Accent.TButton', background=[('active', '#ff6a7d'), ('disabled', '#553440')])
    style.configure('Nav.TButton', background=c['sidebar'], anchor='w', padding=(16, 12))
    style.map('Nav.TButton', background=[('pressed', c['field']), ('active', c['field'])])
    style.configure('Selected.Nav.TButton', background=c['field'], foreground=c['accent'])
    style.configure('TEntry', fieldbackground=c['field'], insertcolor=c['text'], padding=7, borderwidth=1)
    style.configure('TCombobox', fieldbackground=c['field'], background=c['field'], foreground=c['text'], padding=5)
    style.map('TCombobox', fieldbackground=[('readonly', c['field'])], foreground=[('readonly', c['text'])])
    style.configure('Treeview', background=c['panel'], fieldbackground=c['panel'], foreground=c['text'], rowheight=32, borderwidth=0)
    style.map('Treeview', background=[('selected', '#384056')], foreground=[('selected', 'white')])
    style.configure('Treeview.Heading', background=c['field'], foreground=c['muted'], padding=(8, 7), relief='flat')
    style.configure('TCheckbutton', background=c['bg'], foreground=c['text'], padding=4)
    style.map('TCheckbutton', background=[('active', c['bg'])], foreground=[('disabled', '#697589')])
    style.configure('TLabelframe', background=c['bg'], bordercolor=c['border'])
    style.configure('TLabelframe.Label', foreground=c['muted'])
    return style


def card(parent, title):
    frame = ttk.Frame(parent, style='Card.TFrame', padding=18)
    ttk.Label(frame, text=title, style='CardHeading.TLabel').pack(anchor='w', pady=(0, 12))
    return frame


def build(d):
    d.style = theme(d.window)
    shell = ttk.Frame(d.window)
    shell.pack(fill='both', expand=True)
    side = ttk.Frame(shell, style='Sidebar.TFrame', width=190, padding=(14, 20))
    side.pack(side='left', fill='y'); side.pack_propagate(False)
    mark = tk.Canvas(side, width=38, height=28, background=COLORS['sidebar'], highlightthickness=0)
    mark.pack(anchor='w', padx=12)
    mark.create_line(3, 22, 13, 7, 25, 7, 35, 22, fill=COLORS['accent'], width=3)
    mark.create_line(5, 22, 33, 22, fill=COLORS['muted'], width=2)
    ttk.Label(side, text='ExitLag Bridge', background=COLORS['sidebar'], font=('DejaVu Sans', 12, 'bold')).pack(anchor='w', padx=12, pady=(12, 3))
    ttk.Label(side, text='ARCH LINUX  /  x86_64', background=COLORS['sidebar'], foreground=COLORS['muted'], font=('DejaVu Sans', 8)).pack(anchor='w', padx=12, pady=(0, 28))
    names = (('home', 'Главная'), ('games', 'Игры'), ('statistics', 'Статистика'), ('setup', 'Настройки'), ('diagnostics', 'Диагностика'))
    d.nav_buttons = {}
    for key, label in names:
        button = ttk.Button(side, text=label, style='Nav.TButton', command=lambda page=key: d.show_page(page))
        button.pack(fill='x', pady=3); d.nav_buttons[key] = button
    ttk.Button(side, text='Выход', style='Nav.TButton', command=d.close).pack(side='bottom', fill='x')
    ttk.Label(side, text='Экспериментальная\nLinux-совместимость', background=COLORS['sidebar'], foreground=COLORS['muted'], font=('DejaVu Sans', 8)).pack(side='bottom', anchor='w', padx=12, pady=16)
    main = ttk.Frame(shell, padding=(24, 18)); main.pack(side='left', fill='both', expand=True)
    header = ttk.Frame(main); header.pack(fill='x', pady=(0, 18))
    d.page_title = tk.StringVar(value='Главная')
    ttk.Label(header, textvariable=d.page_title, style='Title.TLabel').pack(side='left')
    ttk.Label(header, textvariable=d.session_status, style='Muted.TLabel').pack(side='right')
    # The connection bar remains visible on every page.
    connection = ttk.Frame(main, style='Card.TFrame', padding=(16, 12)); connection.pack(side='bottom', fill='x', pady=(14, 0))
    status = ttk.Frame(connection, style='Card.TFrame'); status.pack(side='left', fill='both', expand=True)
    for column, (title, variable) in enumerate((('BACKEND', d.backend_status), ('EXITLAG', d.client_status), ('МАРШРУТ', d.relay_status))):
        cell = ttk.Frame(status, style='Card.TFrame'); cell.grid(row=0, column=column, sticky='nw', padx=(0, 18))
        ttk.Label(cell, text=title, style='CardMuted.TLabel', font=('DejaVu Sans', 8)).pack(anchor='w')
        ttk.Label(cell, textvariable=variable, style='Card.TLabel', wraplength=195).pack(anchor='w', pady=(5, 0))
    d.primary_button = ttk.Button(connection, text='Подключить', style='Accent.TButton', command=d.toggle_session)
    d.primary_button.pack(side='right', padx=(12, 0))
    d.launch_button = d.primary_button
    workspace = ttk.Frame(main); workspace.pack(fill='both', expand=True)
    d.pages = {key: ttk.Frame(workspace) for key, _ in names}
    d.page_names = dict(names)

    home = d.pages['home']
    home_options = ttk.Frame(home); home_options.pack(side='bottom', fill='x', pady=(10, 0))
    columns = ttk.Frame(home); columns.pack(fill='both', expand=True)
    saved = card(columns, 'Мои игры'); saved.pack(side='left', fill='both', padx=(0, 16))
    saved.configure(padding=14)
    d.manage_button = ttk.Button(saved, text='Добавить / изменить', command=d.games); d.manage_button.pack(side='bottom', fill='x', pady=(12, 0))
    ttk.Entry(saved, textvariable=d.saved_query, width=24).pack(fill='x', pady=(0, 10))
    d.game_list = ttk.Treeview(saved, show='tree', selectmode='browse', height=7)
    d.game_list.column('#0', width=200, minwidth=130); d.game_list.pack(fill='both', expand=True)
    d.game_list.bind('<<TreeviewSelect>>', d.select_game)
    details = card(columns, 'Выбранная игра'); details.pack(side='left', fill='both', expand=True)
    details.configure(padding=14)
    ttk.Button(details, text='Выбрать работающую игру', command=lambda: d.show_page('games')).pack(side='bottom', anchor='w', pady=(10, 0))
    ttk.Label(details, textvariable=d.selected_game, style='CardHeading.TLabel', wraplength=440).pack(anchor='w', pady=(4, 10))
    ttk.Label(details, textvariable=d.selected_details, style='CardMuted.TLabel', wraplength=440, justify='left').pack(anchor='w')
    ttk.Label(home_options, text='Все сохранённые привязки действуют в сессии. Выбранная карточка не ограничивает маршрутизацию одной игрой.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=(14, 8))
    d.udp_toggle = ttk.Checkbutton(home_options, text='Экспериментальный UDP', variable=d.udp_enabled, command=d._sync_controls)
    d.udp_toggle.pack(anchor='w')
    ttk.Label(home_options, text='Выключен по умолчанию. UDP требует отдельной проверки игры; обнаружение процесса не подтверждает реле.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=(2, 8))
    ttk.Label(home_options, textvariable=d.message, style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=(6, 0))

    games = d.pages['games']
    process_details = ttk.Frame(games); process_details.pack(side='bottom', fill='x')
    ttk.Label(games, text='Сетевые процессы вашего пользователя. Имя и AppID помогают найти игру; привязка проверяется перед сохранением.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=(0, 12))
    toolbar = ttk.Frame(games); toolbar.pack(fill='x', pady=(0, 10))
    ttk.Label(toolbar, text='Название / Steam AppID').pack(side='left', padx=(0, 10))
    d.process_search = ttk.Entry(toolbar, textvariable=d.process_query); d.process_search.pack(side='left', fill='x', expand=True)
    d.scan_button = ttk.Button(toolbar, text='Обновить', command=d.scan_processes); d.scan_button.pack(side='left', padx=(10, 0))
    ttk.Checkbutton(games, text='Показать служебные процессы', variable=d.show_technical, command=d.render_processes).pack(anchor='w')
    process_list = ttk.Frame(games); process_list.pack(fill='both', expand=True, pady=8)
    d.process_tree = ttk.Treeview(process_list, columns=('name', 'pid', 'runtime', 'transport', 'appid'), show='headings', height=6, selectmode='browse')
    for key, title, width in (('name', 'Игра / процесс', 260), ('pid', 'PID', 70), ('runtime', 'Среда', 110), ('transport', 'Сокеты', 100), ('appid', 'Steam AppID', 110)):
        d.process_tree.heading(key, text=title); d.process_tree.column(key, width=width, minwidth=60)
    scroll = ttk.Scrollbar(process_list, orient='vertical', command=d.process_tree.yview)
    d.process_tree.configure(yscrollcommand=scroll.set)
    scroll.pack(side='right', fill='y'); d.process_tree.pack(side='left', fill='both', expand=True)
    d.process_tree.bind('<<TreeviewSelect>>', d.select_process)
    ttk.Label(process_details, textvariable=d.process_details, wraplength=850, justify='left').pack(anchor='w', pady=5)
    ttk.Label(process_details, textvariable=d.process_warning, foreground='#f4be77', wraplength=850).pack(anchor='w', pady=3)
    actions = ttk.Frame(process_details); actions.pack(fill='x', pady=(8, 0))
    d.add_process_button = ttk.Button(actions, text='Добавить выбранный процесс', command=d.add_selected_process, state='disabled'); d.add_process_button.pack(side='left')
    ttk.Button(actions, text='Редактировать / удалить привязки', command=d.games).pack(side='left', padx=10)
    ttk.Label(process_details, textvariable=d.scan_status, style='Muted.TLabel').pack(anchor='w', pady=8)

    stats = d.pages['statistics']
    actual = card(stats, 'Состояние текущей сессии'); actual.pack(fill='x', pady=(0, 16))
    ttk.Label(actual, textvariable=d.statistics, style='Card.TLabel', justify='left').pack(anchor='w')
    ttk.Label(stats, text='Сетевые измерения', style='Heading.TLabel').pack(anchor='w', pady=(4, 12))
    measurements = ttk.Frame(stats); measurements.pack(fill='x')
    for index, name in enumerate(('Ping', 'Потери', 'Jitter', 'Объём трафика')):
        box = card(measurements, name); box.grid(row=0, column=index, sticky='nsew', padx=(0, 10)); measurements.columnconfigure(index, weight=1)
        ttk.Label(box, text='Не измеряется', style='CardMuted.TLabel').pack(anchor='w')
    ttk.Label(stats, text='Графики недоступны: desktop не получает эти измерения. Запуск клиента и счётчики сокетов не доказывают передачу через реле.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=18)

    setup = d.pages['setup']
    vendor = card(setup, 'Официальный клиент'); vendor.pack(fill='x')
    ttk.Label(vendor, text='Установите оригинальный Windows-клиент и войдите в него со своим аккаунтом. Пароли и подписка остаются в официальном клиенте.', style='CardMuted.TLabel', wraplength=820).pack(anchor='w')
    line = ttk.Frame(vendor, style='Card.TFrame'); line.pack(fill='x', pady=(18, 0))
    ttk.Button(line, text='Сайт загрузки ExitLag', command=d.open_download).pack(side='left')
    d.choose = ttk.Button(line, text='Выбрать установщик .exe', command=d.install); d.choose.pack(side='left', padx=10)
    ttk.Label(setup, text='В мастере используйте C:\\ExitLag и снимите Launch ExitLag. Известное предупреждение NDIS описано в документации; другие ошибки требуют диагностики.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=18)
    ttk.Label(setup, text='Выбор серверов и применение маршрутов выполняются в официальном клиенте. Bridge не подменяет его каталог или решения.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=8)
    ttk.Label(setup, textvariable=d.message, wraplength=850).pack(anchor='w', pady=12)

    diag = d.pages['diagnostics']
    ttk.Label(diag, text='Локальная сводка и доступные логи. Секреты и полные пути скрываются перед показом и копированием.', style='Muted.TLabel', wraplength=850).pack(anchor='w', pady=(0, 12))
    tools = ttk.Frame(diag); tools.pack(fill='x', pady=(0, 10))
    d.diagnostics_button = ttk.Button(tools, text='Обновить диагностику', command=d.refresh_diagnostics); d.diagnostics_button.pack(side='left')
    ttk.Button(tools, text='Копировать', command=d.copy_diagnostics).pack(side='left', padx=10)
    d.diagnostics_text = tk.Text(diag, wrap='word', height=16, background=COLORS['panel'], foreground=COLORS['text'], insertbackground=COLORS['text'], relief='flat', padx=14, pady=14, font=('DejaVu Sans Mono', 9), state='disabled')
    d.diagnostics_text.pack(fill='both', expand=True)
    d.set_diagnostics_text('Нажмите «Обновить диагностику». Привилегированный лог может быть недоступен обычному пользователю.')
    d.saved_query.trace_add('write', lambda *_: d.render_saved_games())
    d.process_query.trace_add('write', lambda *_: d.render_processes())
    d.show_page('home')
