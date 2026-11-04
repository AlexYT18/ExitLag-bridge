# Итерация: lifecycle, UDP, выбор процессов и сборка пакета

База — `1753efddb4ee77484567ab9fa67ae40b3f142703`. Цель — Arch Linux
x86_64; выполнение ниже происходило в Debian Cloud, а не на Arch desktop.
Изменения публикуются отдельными коммитами в `arch-linux-hardening` форка
`AlexYT18/ExitLag-bridge`, PR #1. Это экспериментальная сборка.

## Изменения в согласованном порядке

1. `14743de` — lifecycle shim. Раньше stop не join-ил workers и следующий init
   мог заменить handler до завершения старого callback. Теперь короткий gate
   сериализует lifecycle, сохраняются HANDLE, внешний free отзывает authority,
   shutdown-ит принадлежащий worker socket и ждёт завершения. Connect использует
   отменяемый nonblocking loop. Повторный init не заменяет активный handler.
   [Контракт и ограничения](../shim-lifecycle.md).
2. `f1ae01b` — UDP. Loopback reverse reply обновляет idle timestamp. Reaper
   сохраняет cursor, удаляет максимум четыре endpoint за reactor turn и делит
   один настроенный RPC deadline между уведомлениями. Session reset прерывает
   старый scan. Capacity diagnostics ограничены одним сообщением в секунду.
   Новая чистая time/scheduler module и тест настоящих daemon call sites
   используют обычные IPv4/IPv6 sockets без root.
3. `3eb5ed9` — выбор процессов. Сортировка колонок, числовой порядок PID,
   socket count/AppID, Clear, Ctrl+F, F5 и переход в список стрелкой вниз.
   Сортировка сохраняет выбранный image, скрытый фильтром выбор отменяется.
   Проверки UID, process generation, socket ownership и PE image сохранены.
4. `eed7401` — исправление гонки старого теста relay counters. Production
   macOS adapter не менялся. Тест ждёт полного окончания flow перед чтением
   счётчиков; все ожидаемые значения сохранены.
5. `9308317` — сборка Linux payloads установленным LLVM без Zig, проверка ABI,
   payload hashes и отдельная версия пакета `0.4.0+arch.1`. В manifest пакета
   записываются revision и hashes файлов. Упаковываются только три необходимых
   compatibility payloads, исключая посторонние файлы и account state.

Core nfapi сохраняет прежние 18 exports/ordinals. Linux installer сохраняет
прежнюю packaged ABI из 20 exports: core18 и два существовавших entry points
управления Windows driver, которые явно возвращают unsupported. В LLVM package
используется обычный `DllMain`; macOS Qt timer entry point не активируется.
Проверка exported names выполняется при сборке, а официальный клиент дополнительно
проходит существующую проверку импортов во время setup. Это не сертификат
совместимости с будущими ExitLag updates.

## Проверки и воспроизведение

```sh
bash tests/test-shim-lifecycle.sh
bash tests/test-shim-lifecycle.sh --sanitize
make -C backend check-udp-lifecycle check-udp-maintenance
python3 tests/test_game_picker.py
python3 tests/gui-picker-smoke.py
python3 tests/test_build_runtime.py
python3 tests/test_linux_packaging.py
python3 tests/cloud_checks.py --sanitizers --output-dir build/cloud-validation
bash tests/run-isolated.sh
```

- Lifecycle: 243 assertions с настоящими native threads, обычная и
  ASan/UBSan сборки PASS; 100 restart cycles, concurrent init/free, partial
  startup failure, callback reentry и deferred self-stop. IPC 5526,
  attribution 1100 и PID domain 1882 assertions PASS, PE linkage PASS.
- UDP scheduler и реальные daemon call sites PASS, включая IPv4/IPv6 reverse
  activity, запрет revival закрытого socket, очистку 9 endpoints за 4/4/1 и
  session reset при disconnect внутри close RPC. ASan/UBSan PASS.
- L2: **8 групп PASS, 0 FAIL, 1 SKIP**, в собственных user/network/PID/mount
  namespaces. Пропущен multi-UID security suite: нет sudo и нескольких mapped
  UID. TCP, legacy UDP и multi-endpoint UDP используют явно синтетические
  callbacks и локальные servers; host firewall не изменялся.
- Process picker: 28 headless methods и 10 actual Tk/Xvfb methods PASS;
  process discovery model 39 methods PASS. Это synthetic/model evidence.
- Runtime build orchestration: 7 methods PASS; packaging: 10 methods PASS.
  Отдельно действительно собраны native helper, nfapi, nfextlag и patched
  wbemprox; это не fixture payloads. Три payload hashes и actual PE exports
  проверены.
- Настоящий pinned Wine 11.17 в private Xvfb прошёл fresh prefix/WMI bootstrap,
  повторную подготовку, account-preserving removal и scoped purge. Официальный
  клиент не устанавливался. Этот тест не загружает nfapi callbacks и не
  подтверждает runtime shim lifecycle.

**Финальный L1: 68 групп PASS, 0 FAIL, 2 SKIP**, exit 0, для кода
`9308317`. [JSON](evidence/reliability-final-cloud.json),
[сводка](evidence/reliability-final-cloud.txt). Два SKIP — отдельный L2 runner
(выполнен выше) и live L3. [L2 evidence](evidence/reliability-isolated.txt),
[Wine/WMI](evidence/reliability-fresh-wine.txt),
[payload build](evidence/reliability-payload-build.txt),
[build tests](evidence/reliability-runtime-tests.txt),
[package tests](evidence/reliability-package-tests.txt).
[Первый L1](evidence/reliability-cloud-initial.txt) и
[воспроизведение гонки](evidence/reliability-metrics-race.txt) сохранены. Отдельные assertions, unittest methods и aggregate groups не складываются
в число поддерживаемых игр.

### Найденные проблемы проверок

Первый L1: **67 PASS, 1 FAIL, 2 SKIP**. Старый relay metrics test читал
snapshot после учёта входящих bytes, но до учёта исходящих. Управляемый порядок
потоков воспроизвёл это состояние; исправление ждёт завершения flow, без retry
и ослабления значений counters. Исправленный suite: 34 PASS, 2 платформенных
SKIP из 36 methods.

Дополнительная sanitizer-сборка daemon-including test с необязательным `-Werror`
остановилась на GCC diagnostics в существующих log/copy call sites. Обычная
release-сборка с `-Werror` и стандартные ASan/UBSan flags проходят; warnings
не подавлялись. Это ограничение дополнительной комбинации compiler flags.

Для сборки Wine в Cloud недостающие bison/flex/m4 были распакованы без root
после проверки SHA-256 по Debian package index. Первая попытка выявила hardcoded
path к m4; BISON_PKGDATADIR/M4 заданы для unpacked tools. Один ошибочно запущенный
конкурентный WMI make повредил временную import library; он остановлен, serial
build повторён успешно. Для воспроизведения на Arch установите нормальные
пакеты по [инструкции](../arch-linux.md), без Cloud overrides.

## Security и оставшиеся ограничения

- Новый lifecycle не позволяет старому worker пережить внешний free и заменить
  состояние новой session. Socket shutdown/close сериализованы, чтобы reused
  numeric handle не затронул чужой socket. Thread termination не используется.
- Self-free из callback откладывает join: handler и DLL должны жить до внешнего
  free. Зависший proprietary callback или длинная research injection command
  может задержать внешний free; принудительное уничтожение небезопасно.
- Отложенная очистка UDP не даёт authority устаревшим owners: packet path
  продолжает generation/tuple checks. Нет claims о росте throughput или
  уменьшении latency без сравнительных измерений.
- Manifest проверяет целостность, но не является цифровой подписью. Пакет не
  содержит ExitLag installer, credentials или subscription data. Аккаунт вводится
  пользователем внутри официального клиента. Root нужен только native helper.
- Асинхронные UDP posts, arbitrary controls/options, policy-routing/VPN
  coexistence, shared-fd attribution и game compatibility остаются ограничениями
  [UDP contract](../udp-multi.md). Производительность и нагрузка не измерены.

## Следующий шаг: настоящий ExitLag и PEAK

Этот шаг **BLOCKED / NOT TESTED**: в доступном Cloud нет установленного клиента,
аккаунта/подписки и PEAK/Steam host. Никакие synthetic результаты не заменяют
этот этап. Подготовлена [пошаговая процедура PEAK](../peak-validation.md) с
отдельными DETECTED, INSPECTED, REDIRECT REQUESTED, REDIRECT APPLIED,
RELAY TRAFFIC VERIFIED и GAMEPLAY VERIFIED. Секреты передавать разработчику
не требуется. Реальные проверки на Arch в эту итерацию не включены.
