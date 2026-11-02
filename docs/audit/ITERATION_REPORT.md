# Результат инженерной итерации: Arch Linux x86_64

Исходная версия аудита: `c0525a74c35fd74c815326d957c21a593a6aaccb`. По последующей просьбе пользователя изменения оформлены отдельными коммитами для ветки `arch-linux-hardening` форка `AlexYT18/ExitLag-bridge`. Первоначальный аудит и тесты выполнялись без project commits. Целевая платформа после уточнения пользователя — **только Arch Linux x86_64**. Код других платформ сохранён, но новых обязательств по их поддержке нет.

Это проверенный результат аудита и исправлений экспериментального проекта, **не готовый стабильный универсальный игровой релиз**. Настоящий ExitLag, подписка, игры и трафик через коммерческие реле в этой итерации не использовались.

## Что исследовано

Все 185 исходных tracked-файлов классифицированы в [FILE_INVENTORY.md](FILE_INVENTORY.md), включая backend, shim, discovery/tools, установщики, macOS, Wine patch, тесты, CI, документацию и лицензии. [INITIAL_AUDIT.md](INITIAL_AUDIT.md) и отдельные отчёты содержат доказательства, серьёзность и ссылки на строки исходного коммита. Подтверждённые ошибки отделены от гипотез.

## Что изменено и почему

| Область | Исправление | Проверка и границы |
| --- | --- | --- |
| IPC daemon | Выделен `backend/ipc_transport.{c,h}`; общий monotonic deadline на отправку/чтение/целый RPC; nested/stale frames не продлевают ожидание; проверяются flags и точные размеры | Нативные socketpair tests, 16 тестов настоящего daemon `--no-queue`, повтор под ASan/UBSan. Callback loop остаётся синхронным; handshake кандидата может задержать его до 2 секунд |
| Аутентификация | Неверный кандидат не вытесняет действующий shim; повторный HELLO и malformed framing отвергаются | Проверки bad token/version/flags, replacement, восстановление после disconnect. Токен защищает границу аккаунта, а не все процессы того же UID |
| Identity | Убрано доверие argv/argv0 в strict и no-map; native identity берётся из `/proc/PID/exe`; prefix mapping привязан к явно разрешённому executable | Положительные/отрицательные IPC-тесты, 11 utility tests, 50 независимых прогонов после исправления готовности fixtures. PID/exec-generation и сложная атрибуция остаются открытыми |
| Wire/shim | Общий `backend/protocol.h`, 15 compile-time layout checks; единый лимит payload; строгий loopback parser; проверка PID reply span/reserved/output capacity | 5505 assertions в одном native regression executable, повтор с sanitizers; сборка x64 PE; 18 имён/ordinal экспортов совпадают с baseline. Это не проверка proprietary callback ABI под Wine |
| Диагностика | Убраны UDP payload/hash из обычных логов; файлы 0600, no-follow/nonblocking, regular/owner/single-link проверки; anchored rotation | Проверки symlink/FIFO/hardlink/parent symlink, chmod/rotation и synthetic payload canary. Endpoints и executable paths всё ещё требуют редактирования перед публикацией |
| Launcher/lease | Нормализация UTF-16 `tasklist`; cleanup переживает timeout Wine; будущий lease timestamp отвергается; prefix editor понимает OWNER_EXE | 5 headless launcher и 11 supervisor tests. Живой Wine GUI не запускался |
| Сохранённый Mac-код | Неблокирующее чтение config/FIFO, hardlink guard, корректный platform SKIP | Portable loopback/logic regression tests; native macOS/PF не проверены |
| Build | Относительные source paths для CL driver; общий выбор `clang-cl` либо `clang --driver-mode=cl`; доверенные стандартные nft paths и compile-time test override; исправлен `%X`/signed-pointer mismatch | Три настоящие PE-сборки, 3 tests выбора compiler, статанализ, Arch container toolchain. Никакого runtime выбора произвольной root-команды из пользовательского PATH |
| Тесты/CI | JSON PASS/FAIL/SKIP; неизвестный tier и ноль unittest cases не проходят; v3/token TCP/UDP peers; disposable user/net/PID/mount namespaces и локальные серверы; bounded signal tests | Новый CI ориентирован на Arch. Локальный эквивалент проверен; эти результаты не являются запуском GitHub Actions |

Полный перечень файлов: [CHANGED_FILES.md](CHANGED_FILES.md). Прежняя функциональность не заменялась большим rewrite; расширение активного UDP до нескольких endpoints намеренно не выполнено без требуемого покрытия.

## Фактические проверки

| Запуск | PASS | FAIL | SKIP | Что означает |
| --- | ---: | ---: | ---: | --- |
| Arch userspace, обычный пользователь, полный L1 с sanitizers | 35 групп | 0 | 2 группы | Сборки, unit/mock IPC, syntax, ShellCheck, cppcheck, GCC analyzer, ASan/UBSan. L2/L3 запускаются отдельно |
| Debian Cloud, дополнительный L1 regression | 35 групп | 0 | 2 группы | Контрольный host-прогон, не заявление о поддержке Debian |
| Linux Cloud, изолированный L2 | 6 групп | 0 | 1 группа | Настоящие NFQUEUE/nftables, TCP IPv4/IPv6, UDP observe/ограниченный reinjection, crash/recovery/cleanup |
| Отдельный многопользовательский Arch container, IPC `--no-queue` | 23 assertions | 0 | 0 | Неверный UID, token/version, replay после restart, malformed frames, liveness и secret hygiene |
| Прежний unit entry point | 10 групп | 0 | 2 группы | Пропущены проверки, которым нужен установленный официальный клиент |
| Identity regression stress | 50 прогонов | 0 | 0 | Synthetic ELF owners, canonical prefix, argv/argv0 spoofs, no-map и invalid config |
| PE exports baseline/current | 18 совпавших экспортов | 0 | — | Совпадение имён/ordinal, не поведения клиента |

В Arch L1 учтены **158 исполнений unittest methods**, включая повторные запуски и sanitizer-вариант; это не 158 уникальных сценариев и не количество игр. Два внутренних platform SKIP относятся к macOS libproc/PF. Native shim executable проверяет 5505 assertions за запуск; assertions также не следует называть независимыми тестами.

L2 hardening: **9 сценариев PASS, 0 FAIL, 1 SKIP**. Проверены пять start/stop cycles, stale-table refusal, восстановление orphan после SIGKILL runner, bounded SIGTERM/SIGINT с ожидаемым exit status, queue bypass после смерти helper, SIGKILL helper, wrong protocol, unreachable destination и последующее восстановление. Пропущен Wine reconnect smoke: подготовленного Wine runtime/prefix нет. Итоговый firewall/helper cleanup прошёл.

В L2 wrapper межпользовательский legacy IPC test пропущен из-за единственного mapped UID и отсутствия sudo. Остальные auth/framing/token negatives выполнены в L1. Дополнительный многопользовательский Arch container-прогон выполнен отдельно: **23 PASS, 0 FAIL** ([лог](evidence/arch-multiuid.txt)), без подмены SKIP wrapper. Он запускает root helper с `--no-queue` и настоящего клиента другого UID; netfilter не затрагивается.

Arch проверен в контейнере с общим Cloud kernel `6.18.57`, а не при загрузке физической Arch-системы. Образ `archlinux:base` при выполнении имел digest `sha256:e82623936fa1a69700b48e98b058df6eaab18b737c27473a7234a40fdecb9413`; точные версии находятся в [arch-toolchain.txt](evidence/arch-toolchain.txt): GCC 16.2.1, Clang/LLVM 23.1.4, Python 3.14.9, libmnl 1.0.5, cppcheck 2.22.0, ShellCheck 0.11.0. Пакеты Arch rolling обновляются, поэтому одного имени image tag недостаточно для исторической воспроизводимости.

Машиночитаемые результаты: [Arch L1](evidence/arch-l1.json), [host L1](evidence/debian-l1.json), [L2 summary](evidence/isolated-l2-summary.txt), [PE exports](evidence/pe-exports.json). Рядом находятся логи отдельных synthetic checks. Account data, vendor binaries, Wine prefixes и реальные captures в результат не включены.

## Неудачные прогоны и исправления

Базовая версия дала 1/8/7 в первоначальном ограниченном sandbox и 5/4/7 после подготовки зависимостей; подробности в [BASELINE_TESTING.md](BASELINE_TESTING.md). Причины включали недостающие tools, запрещённые sockets, CL parsing абсолютного `/workspace` и сломанный copied-Python fixture.

При разработке были реальные FAIL: незавершённый новый test file, несовпавшая диагностическая строка, неверно переданный compile-time nft path и startup race fixture. Ничего не было объявлено успешным до исправления и повторного запуска. В immediate post-exec наблюдениях `/proc/PID/environ` был пуст в 19/100 случаях; policy assertion сохранён, тест ожидает готовность процесса. После этого 50/50 полных прогонов прошли. В production этот transient пока может означать пропуск начальной возможности mapping; это не исправление общего PID lifecycle.

До уточнения Arch-only выполнен exploratory Ubuntu-прогон: 30 PASS / 1 FAIL / 5 SKIP. Ошибка вызвана заданным harness `HOME=/tmp`, отличавшимся от home тестового пользователя в passwd; три PE checks пропущены из-за отсутствующего alias `clang-cl`. Добавлен проверяемый compiler fallback. Ubuntu после изменения scope не проверяется и не заявляется поддерживаемой платформой. Этот неудачный exploratory результат не скрыт и не включён в Arch acceptance.

## Производительность

Добавлен воспроизводимый `tests/benchmark-ipc.py`, проверяющий корректность всех ответов. По 10 запусков × 1000 PID RPC на baseline и изменённом release daemon, без NFQUEUE, игры или реле:

| Метрика synthetic IPC | Baseline | Изменённый daemon |
| --- | ---: | ---: |
| p50 RPC, ms | 0.0248 | 0.0230 |
| p95 RPC, ms | 0.0624 | 0.0528 |
| p99 RPC, ms | 0.1381 | 0.1226 |
| median RPC/s | 31764 | 32082 |
| median startup с handshake, ms | 3.49 | 3.32 |
| median teardown, ms | 1.14 | 1.13 |
| max helper RSS, KiB | 908 | 916 |
| total helper CPU, s | 0.11 | 0.11 |

Это короткий workload на общей Cloud-машине; scheduling outliers заметно меняют variance. **Улучшение производительности не заявляется.** Не измерены игровой throughput/latency/jitter/loss, NFQUEUE saturation, concurrent-flow capacity и relay overhead. Полные данные и hash бинарников: [baseline](evidence/ipc-baseline.json), [current](evidence/ipc-current.json).

## Повторение на Arch

В обычной пользовательской сессии, после установки зависимостей:

```sh
sudo pacman -S --needed base-devel clang lld llvm libmnl nftables iproute2 python tk shellcheck cppcheck git
make -C backend
bash tests/run-cloud.sh --sanitizers
bash tests/run-isolated.sh
python3 tests/benchmark-ipc.py --binary backend/exitlag-netd --iterations 10 --transactions 1000 --output /tmp/ipc-current.json
```

L1 не требует root. L2 wrapper создаёт отдельные user/network/PID/mount namespaces; при отсутствии возможностей возвращает SKIP 77. Не запускайте legacy network harness напрямую на общей машине. Для baseline benchmark соберите исходный коммит в отдельной папке и передайте его бинарник тому же benchmark script.

Для Cloud, где nft распакован в нестандартный prefix, L2 выполнялся с явно скомпилированным test-only `EXL_NFT_PATH`; после проверки восстановлена обычная release-сборка. На Arch с установленным nftables override не нужен. Сама проверка никогда не меняла host firewall.

## Остаточные риски и следующие приоритеты

1. TCP attribution должна учитывать полный tuple, UID, namespace и process/socket generation; сейчас есть неоднозначности. Нельзя расширять перехват на все приложения, считая это решённым.
2. UDP endpoint reuse, reconnect replay/reset, backpressure, fragments/IPv6 extensions и multi-endpoint lifecycle нуждаются в отдельных модулях и тестах. Общий UDP/IPv6 reinjection не готов.
3. Worker stop/join/re-init в shim, подтверждение NFQUEUE readiness через ACK и единое firewall session ownership остаются открытыми задачами.
4. Prefix allowlist не доказывает конкретный Windows image. Игры с общим prefix требуют аккуратной явной настройки. Имя исполняемого файла не изобретается.
5. NetworkManager/resolved/VPN coexistence, anti-cheat restrictions, client/Wine updates, длительный soak и реальный Arch kernel/desktop требуют локальных испытаний.

План с критериями приёмки: [ROADMAP.md](ROADMAP.md). Новая игровая совместимость в этой итерации не подтверждена: native/Steam/Proton/Wine, TCP/UDP/IPv6, launcher/multi-flow классы остаются **NOT TESTED на уровне реальных игр**. Synthetic REDIRECT APPLIED не означает REDIRECT REQUESTED настоящим ExitLag, RELAY TRAFFIC VERIFIED или GAMEPLAY VERIFIED.

Для следующего live этапа нужен Arch-хост, официальный клиент под подходящим Wine, законная подписка и выбранная игра. Локально фиксируются версии, точный socket owner/mapping, каждый этап pipeline, реальные relay bytes, продолжительность, reconnect и cleanup. Секреты аккаунта разработчику передавать не требуется. Античит, лицензирование и сервисные ограничения не обходятся.

## Подготовка публикации в форке

Публикационная ветка: `AlexYT18/ExitLag-bridge:arch-linux-hardening`. Изменения
разделены на коммиты native IPC/identity/session files, shim/wire/build,
Arch CI/test harness и документации с evidence. Использована публичная noreply
commit metadata; upstream `main` не переписывается.

Перед публикацией ветка перенесена на `dfdd0ee43e2edb850fec31621e8feffa3dea2715`
из `main` пользовательского форка. Сохранены оба новых upstream-коммита:
обзор совместимости клиента 5.24.0 и обработка lock contention Mac status file.
Конфликт документации разрешён сохранением и upstream-обзора, и границ
доказательств аудита. Локальные исследования не подтверждают login/gameplay
нового клиента.

Повторный Arch L1 после объединения: **35 PASS / 0 FAIL / 2 SKIP**,
**159 исполнений unittest methods**, включая повторные проверки; два внутренних
platform SKIP. Дополнительный upstream test увеличил число methods относительно
исходного отчёта 158. См. [результаты](evidence/arch-publish-l1.json),
[summary](evidence/arch-publish-summary.txt) и
[portable Mac regressions](evidence/arch-publish-macos-units.txt).
Из Linux backend/shim/network harness после первоначальной L2 проверки ничего
не изменено. GitHub-hosted workflow не считается выполненным на основании
локального container-прогона.

Автоматический CI в этой ветке ограничен Arch и source privacy. Унаследованный
Ubuntu installer workflow сохранён с ручным запуском; его ранее начавшийся
PR-прогон отменён как находящийся вне Arch-only scope. Ключ кеша Windows
payloads теперь учитывает общий `backend/protocol.h`, чтобы обновление wire
contract не переиспользовало несовместимую закешированную DLL.
