# Phase 1 — документация, заявленная совместимость и лицензии

Дата: 2026-11-01. Исходный commit: `c0525a74c35fd74c815326d957c21a593a6aaccb`.
Это техническая проверка checkout, без изменения runtime и без юридического заключения.

## Объём и метод

Проверены 61 tracked-файл: все 29 файлов `docs/`, `README.md`,
`CONTRIBUTING.md`, `THIRD_PARTY.md`, `LICENSE`, все 26 файлов `LICENSES/`,
`.gitignore` и `.gitattributes`. Технические утверждения выборочно сопоставлены
с указанным в findings кодом; этот файл не подменяет аудит backend/установщиков.
Тексты лицензий проверялись как upstream notices с разграничением применимости,
а не как доказательство полной юридической чистоты бинарных релизов.

`docs/social-card.png` проверен по метаданным: PNG, 1200×630, RGBA,
SHA-256 `10306d1ef652743cdf2b7194557f4bfe4bff575e2bdf78bb331df801a7a3d8ff`.
`docs/.nojekyll` пуст. `favicon.svg`, CSS, HTML, sitemap, llms.txt и release JSON
прочитаны как текст. Офлайн-проверка 38 локальных Markdown/HTML ссылок дала
0 отсутствующих целей. Внешние ссылки/CI run/release assets этой проверкой
не скачивались и не подтверждались.

## Что заявлено и что можно подтвердить сейчас

| Область | Публичное утверждение | Подтверждение checkout и предел |
|---|---|---|
| Архитектура | Bridge перехватывает/атрибутирует трафик, официальный клиент выбирает маршрут и транспортирует к relay | Согласованная модель в README, FAQ, сайте и technical docs. Самостоятельного remote route API здесь не заявлено. Динамическая проверка с клиентом не выполнена в этом подаудите. |
| Linux WoW | Classic Era работает на Arch с исходным bridge | Это зафиксированный отчёт maintainer, а не воспроизведённый результат текущего packaged install. В `compatibility.md:16` и `arch-linux.md:61` различие указано корректно. |
| Linux пакеты | Один архив для Ubuntu 22.04/24.04 и Arch userspace | Имеются release JSON и CI ссылки. Arch container использует Ubuntu host kernel; native Arch kernel и новая vendor-install/login/gameplay цепочка не подтверждены. |
| macOS | Apple Silicon, target macOS 15+, WoW, IPv4 TCP | README/FAQ/site/llms согласованы. Заявленная live-система — macOS 27.2; macOS 15 как минимальная система отдельно не подтверждена. Intel, UDP и IPv6 не заявлять. |
| Другие игры | Minecraft unstable; Dota 2/Tibia detection only; остальные untested | Таблицы README/compatibility/site согласованы. Эти опыты исторические и не воспроизведены на новом installer. |
| Linux IPv6 TCP | Механизм проверен synthetic peer | `ipv6-active-rewrite.md` корректно отделяет synthetic от реального vendor redirect; текущий backend содержит AF_INET6 rewrite. Ни один live IPv6 title не подтверждён. |
| Отказоустойчивость | Сбой helper позволяет трафику идти дальше | Правильное направление дизайна, но абсолютные заявления в architecture шире зафиксированных опытов; см. DOC-05. |
| Лицензии/provenance | First-party GPL-3.0-only; runtime third parties сохраняют лицензии; исходное происхождение части ABI не полностью установлено | Notices присутствуют, limitation явно отражён. Это не legal clearance и не автоматическое требование коммерческой SDK лицензии. |

## Findings

Приоритеты: P1 — исправить перед расширением публичных гарантий; P2 — сделать
до следующего релиза; P3 — поддержка и редактура. Статус каждого finding —
**открыт**, если явно не сказано иначе.

| ID / приоритет | Наблюдение и точное место | Последствие / критерий исправления |
|---|---|---|
| DOC-01 / P1 | `docs/architecture.md:77` перечисляет loopback среди запрещённых target. Но README security section, `rpc-surface.md:36`, `ipv6-active-rewrite.md:43` и `backend/exitlag-netd.c:1859–1901` требуют loopback по умолчанию. | Противоречие в основной security boundary. Описать отдельно invalid unicast и отказ от **non-loopback**, включая IPv4-mapped IPv6 loopback; связать с существующими negative tests. |
| DOC-02 / P2 | `docs/rpc-surface.md:31–32` описывает только IPv4 и `AF_INET`; `architecture.md:184` относит non-IPv4 mutation к fail-open. Backend и IPv6 doc поддерживают IPv6 TCP. | Security specification отстаёт от реализации. Документировать семейства, sockaddr offsets, loopback-only, synthetic evidence и отсутствие live IPv6 route. |
| DOC-03 / P2 | `docs/testing.md:14–16` даёт 16 full / 9 fresh + 2 skip; `docs/test-matrix.md:66` даёт 10 / 5 + 2. В текущем `tests/run-all.sh` зарегистрировано 11 unit + 4 system + 1 live. | Разные числа выглядят как результаты текущего исходника. Привязать все результаты к commit, среде, дате и логам; генерировать перечень из runner либо убрать hardcoded latest counts. Наличие теста не считать его PASS. |
| DOC-04 / P1 | `docs/pipeline-stages.md:25–26,99–104` говорит, что все ошибки были только в vendor stages 1/3, а 2/4 не ошибались. `docs/runtime-hardening.md:99–104` сам описывает defect production debug-policy, вызывавший отказ UDP. `pipeline-stages.md:72` причинно исключает bridge на основании одного A/B. | Нельзя переносить ограниченные исторические наблюдения на все отказы или исключать compatibility bug без Windows control. Разделить измеренное, гипотезу и неизвестное; ограничить выводы конкретной версией и сценарием. |
| DOC-05 / P1 | `docs/architecture.md:178–185` обещает, что потеря ПО ни в какой конфигурации не ломает сеть; `:196` объединяет normal exit и SIGKILL cleanup. `runtime-hardening.md:26–29` точнее говорит, что SIGKILL runner оставляет recovery **на следующий старт**. | Сузить обещания: какие новые flows идут unchanged, что происходит с уже DNATed established flow, умершим local proxy, queue saturation, SIGKILL owner и table lifetime. `queue bypass` само по себе не доказывает сохранение relay session. Проверка runtime принадлежит backend-аудиту; документация должна ссылаться на его точные результаты. |
| DOC-06 / P2 | `docs/runtime-hardening.md:87–90` утверждает отказ для каждого unverified build. `tools/run-exitlag-production.sh:31–45` допускает неизвестный build после успешного ABI check; `exitlag-updates.md` это описывает правильно. | Привести hardening doc к warn-and-run для static-ABI-compatible drift и refuse для несовместимого ABI. Не называть static check подтверждением поведения клиента. |
| DOC-07 / P2 | `docs/runtime-hardening.md:142–144` и конец `wine-stub-crash-guards.md` советуют убивать sleep child, потому что сигнал не запускает trap. Активные runners теперь вызывают `runtime_guard_wait` и имеют INT/TERM traps (`backend/run-tcp-redirect.sh:47–48,70`, `run-udp-steer.sh:55–57,84`). | Старое troubleshooting может заставить пользователя завершать неправильный процесс. Отметить прежний дефект как историю; документировать текущий stop/recovery и безопасные PID-specific команды. |
| DOC-08 / P2 | `docs/repository-layout.md:3–5,63–84` обещает, что research перенесён, а не удалён, и описывает `research/`, `runtime/` как часть дерева. `git ls-files research runtime` пуст для публичного snapshot. `wine-stub-crash-guards.md` ссылается на отсутствующие `runtime/backups/...`; raw traces намеренно не опубликованы. | Разделить tracked layout, создаваемый runtime и исторические непубличные материалы. Явно назвать evidence unavailable in checkout; добавить redacted воспроизводимые summaries без аккаунтов и raw packets. |
| DOC-09 / P2 | `docs/wine-setup.md:6,25–42` описывает project-local patched Wine, `architecture.md:207` — prefix-local WMI; packaged setup использует payload из `installers/build_runtime.py`, а developer override script специально disabled. | Ввести явные маршруты developer vs installed package и архитектуры/версии runtime. Не смешивать инструкции копирования DLL и сборки полного локального Wine. |
| DOC-10 / P2 | `docs/releases/v0.4.0-alpha.2-validation.json` содержит `source_commit`, старые counts, original snapshot label и более поздние CI extensions, но не привязывает каждый результат к отдельному source/artifact digest. | Этот файл полезен как историческая запись, не как proof current HEAD. Для каждого run фиксировать commit, artifact hash, kernel/userspace, command, pass/fail/skip и date. Не переписывать старый snapshot новыми результатами без scope. |
| DOC-11 / P3 | На странице `docs/index.html:63` Mac download назван `unsigned beta`, хотя весь релиз `0.4.0-alpha.2`/experimental. `docs/security-review.md:91` дублирует heading `Input validation`. | Согласовать release terminology и убрать editorial defect. |

Дополнительно: README:244 называет отображение внешнего процесса в UI
untested, а architecture:220–221/pipeline-stages:49 заявляют наблюдавшуюся
сессию Dota 2. Это может быть разница между process list и session panel,
но документы не определяют её. Дать точные названия UI и отдельные evidence
states, сохраняя правило: dashboard entry не доказывает relay routing.

## Лицензии и происхождение

| Объект | Найдено | Остаётся проверить |
|---|---|---|
| First-party | Полный GPLv3 в `LICENSE`; README, CONTRIBUTING и THIRD_PARTY явно выбирают GPL-3.0-only. | LICENSE сам содержит стандартный текст с примерами `or later`; не менять upstream license text. При необходимости закреплять intended SPDX scope в исходниках/metadata и binary source manifest. |
| Wine WMI patch | `LICENSES/LGPL-2.1.txt`, attribution и pinned upstream; builder создаёт `exitlag-bridge-wine-source.tar.gz`; workflow перечисляет source archive. | Наличие build logic не доказывает, что публичный binary asset сопровождается точным corresponding source, patch и build instructions. Это отдельная проверка release artifacts. |
| libmnl | THIRD_PARTY: системная dynamic dependency, LGPL-2.1-or-later. | Подтвердить binary linkage и фактическое отсутствие vendored libmnl в каждом release archive; не обобщать вывод на иной способ линковки. |
| Zig compiler runtime | `LICENSES/Zig-MIT.txt` сохраняет MIT notice; THIRD_PARTY объясняет linked builtins. | Сопоставлять с pinned compiler и фактически включёнными builtins; отсутствие toolchain в installer не отменяет notices для linked runtime. |
| Embedded CPython | `PROVENANCE.txt` указывает PBS 20261026 и commit `fa506e0858ac9f2cc5b289c137b888a2aa24d1ee`; catalog pin 3.13.18 согласован. Есть CPython license и отдельные native dependency notices. | Нужен per-platform runtime manifest/SBOM. Upstream коллекция включает разные платформы; наличие текста не означает, что соответствующая библиотека включена в macOS бинарь. |
| PBS collection | `LICENSES/python-standalone/LICENSE` — **MPL-2.0**, а не CPython PSF; `python-licenses.rst` включает gdbm/readline GPLv3, legacy OpenSSL, Berkeley DB source-availability условия. Отдельный `LICENSE.openssl-3.txt` содержит Apache-2.0. | Не сводить всё дерево к «PSF/MIT». Сохранить upstream notices verbatim и определить применимость к выбранному archive, особенно GPL/source obligations и legacy vs actual OpenSSL. Без binary manifest нарушение не установлено. |
| nfapi ABI | `THIRD_PARTY.md:47–67` и provenance review честно фиксируют неполную историю происхождения layouts, exports и vtable. | Получить authoring evidence либо квалифицированный review exact revision. Совпадение API само по себе не устанавливает ни нарушение, ни обязательность коммерческой лицензии. Этот аудит не отправлял external inquiries. |
| ExitLag | Документация требует user-supplied official installer/account и отрицает bundled vendor code. | Подтверждение release contents отдельно; наличие notices и `.gitignore` не доказывает отсутствие vendor payload в скачанном asset. |

Все три source fingerprint из `docs/provenance-review.md:25–31` совпали с
текущими `nfapi_stub.cpp`, `nfextlag_stub.c` и `exitlag-netd.c`. Это подтверждает
объект предыдущего технического review, а не воспроизводит его внешние правовые выводы.

`LICENSES/README.md` перечисляет LGPL и Zig, но не объясняет MPL/CPython и
aggregate collection; полезен индекс применимости с сохранением оригинальных
текстов. `.gitattributes` правильно отключает whitespace normalization для
legal notices и Wine patch. `.gitignore` исключает prefixes, vendor binaries,
токены, ключи, env и build outputs, но не является privacy/security проверкой.
CONTRIBUTING запрещает screenshots/raw logs, тогда как старый комментарий
`.gitignore` говорит, что screenshots остаются: уточнить политику для заранее
проверенных redacted evidence и запретить неотредактированные account captures.

## Roadmap и acceptance matrix

| Этап | Изменение | Приёмка |
|---|---|---|
| P1 — границы гарантий | Исправить DOC-01/04/05; определить runtime guarantees по flow/protocol/жизненному циклу | Security prose соответствует validators; утверждения не выходят за конкретные тесты; unsupported и unknown состояния названы явно. |
| P2 — единая спецификация | Обновить RPC IPv6, update policy, stop/recovery, developer/package setup, tracked layout | Сверка с исходником и существующими тестами; ни одной инструкции на отсутствующий required tool; все local links разрешаются. |
| P2 — evidence record | Матрица game×OS×arch×client×Wine×transport×stage; dated per-run records | Для PASS: точный commit/artifact hash, command, среда, redacted observation и результат cleanup; SKIP/нет аккаунта/не тестировалось никогда не превращается в PASS. |
| P2 — clean user scenarios | Повторить свежий Linux GUI install/login/WoW и native Arch; Mac minimum target и второй Mac; reboot/sleep/reconnect и длительную сессию | Отдельные сценарии, воспроизводимые шаги и outcomes. Installer CI не заменяет игровой тест; container Arch не заменяет native kernel. |
| P2 — release provenance | Проверить каждый release asset и corresponding source, runtime license mapping | Архивы соответствуют manifest/hash, без account/vendor state; first-party source и patched Wine source доступны; bundled notices доступны в установленном приложении. |
| P2 — ABI origin | Привязать evidence/review к revision и ABI declarations | Записан источник каждой спорной части или границы отсутствующей информации; ни cosmetic rewrite, ни отсутствие vendor header не выданы за independent-derivation proof. |
| P3 — публикация | Синхронизировать README/site/FAQ/llms/release labels и metrics | Один experimental release label, одинаковые compatibility states; метрики получены из датированного результата текущего runner. |

Acceptance-сценарии для расширения поддержки:

| Сценарий | Минимальное подтверждение | Запрет на вывод |
|---|---|---|
| Новый title/transport | Новая соединённая игровая сессия, callback decision, actual relay path в обе стороны, продолжительность и cleanup | Recognition/счётчики не означают working gameplay. |
| IPv6 TCP production | Настоящий vendor callback возвращает IPv6 redirect, соединение и reverse path работают | Synthetic IPv6 harness не означает поддержку real IPv6 game. |
| Fail-open | Новые и established flows проверены отдельно при helper/proxy/owner crash, queue pressure, reconnect | Успешный новый direct socket не доказывает сохранение прежней relay session. |
| Update compatibility | Static ABI плюс GUI/auth/route/game smoke на exact vendor/Wine build | Неизменённый import/export набор не доказывает неизменный callback contract. |
| macOS release | Exact architecture/minimum OS, helper lifecycle, unsigned status либо verified Developer ID/notarization | Подготовленные signing controls не означают signed/notarized artifact. |

Результат этого подаудита: документация хорошо отделяет основные игровые
ограничения на публичных entry points, но старые technical notes содержат
противоречащие им гарантии и устаревшие числа. Функциональные изменения,
коммиты, внешние обращения и правовые разрешения не выполнялись.
