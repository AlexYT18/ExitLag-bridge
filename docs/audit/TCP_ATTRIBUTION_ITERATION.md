# Итерация: TCP tuple и проверка владельца

База: `e5d456ac322dbab2fb143f412f25a555d7a00e27`, ветка
`AlexYT18/ExitLag-bridge:arch-linux-hardening`, PR #1. Цель — Arch Linux x86_64.
Переписывания на другой язык и расширения активного UDP нет.

## Проблема и изменения

Прежние native и Windows lookup сравнивали только локальный адрес/порт.
Два соединения с общим локальным endpoint, но разными серверами могли получить
одного владельца. Native lookup выделен в `backend/tcp_attribution.{c,h}`:
сравниваются обе пары address/port и family, IPv4-mapped преобразует оба конца,
несколько подходящих inode считаются неоднозначностью. Повреждённая или
нечитаемая таблица не считается доказательством отсутствия другого владельца.

`backend/process_identity.{c,h}` проверяет PID/starttime, четыре UID из status,
владельца proc directory и held socket fd. Перед callback процесс должен
принадлежать разрешённому пользователю; перед установкой DNAT повторно
проверяются tuple→inode и generation/UID/held fd. При ошибке новая redirect
запись не устанавливается. Ни argv, ни comm не используются этим verifier как
доказательство executable identity.

В shim decoder Windows owner tables имеет явные DWORD layout/offset assertions,
проверяет размер буфера/count и полный TCP tuple со scope. NONE/UNAVAILABLE
отличаются от INVALID/AMBIGUOUS; последние не разрешают Linux fallback.
Для IPv4 отсутствие exact owner допускает проверку обоих mapped IPv6 endpoints.
PID0 и неоднозначная identity не вызывают vendor callback; reply обозначает
NO_HANDLER и сохраняет исходные поля, без выдуманного решения ExitLag.

Числовые PID разных ОС больше не перезаписывают origin молча. Atomic registry
содержит до 256 разных PID, не вытесняет старые записи и отказывает при
противоречии Linux/Windows domains. SDK name query перепроверяет origin;
TCP mutation отбрасывается при изменении domain во время callback. UDP owner
cache сохраняет origin; неизвестный PID пропускает callback. UDP table parsing
получил bounds checks, но прежняя неоднозначная wildcard attribution не исправлена.

## Фактические проверки

- Cloud L1: **45 групп PASS, 0 FAIL, 2 SKIP**, включая ASan/UBSan и статанализ.
- Linux namespaces: **6 групп PASS, 0 FAIL, 1 SKIP**. Новый TCP harness держит
  два реальных SYN_SENT от разных subprocess с одинаковым local tuple,
  возобновляет временно остановленный helper и проверяет правильный PID для
  каждого remote, два независимых proxy echo, original peer, незатронутый
  loopback control и cleanup. IPv6 harness проверяет PID реального клиента.
- Native shim attribution: **865 assertions**; PID domains: **1882 assertions**;
  IPC/callback policy: **5526 assertions**, каждый executable пройден также
  под ASan/UBSan. Это assertions, не число независимых тестов или игр.
- Native fixtures/live sockets проверяют malformed proc/stat/status, overflow,
  IPv4/IPv6/mapped, разные remote ports/addresses, close/exit и ownership.
- x64 PE собран; **18 export names/ordinals** совпадают с исходной версией.

Evidence: [L1](evidence/tcp-iteration-cloud.json),
[L1 summary](evidence/tcp-iteration-cloud.txt),
[изолированные проверки](evidence/tcp-iteration-isolated.txt),
[два TCP владельца](evidence/tcp-iteration-concurrent.txt).
Эти результаты получены в Cloud; GitHub Arch CI проверяется после push отдельно.
Официальный клиент, подписка, реальные реле и gameplay не использовались.

```sh
make -C backend check-tcp-attribution check-process-identity
bash tests/test-shim-attribution.sh --sanitize
bash tests/test-shim-pid-domain.sh --sanitize
bash tests/run-cloud.sh --sanitizers
bash tests/run-isolated.sh
```

## Границы и точка продолжения

1. Revalidation не является atomic ownership lock: после проверки процесс может
   закрыть fd; same-UID exec не меняет starttime. Несколько процессов с общим fd
   всё ещё выбираются прежним PID-ranking кодом; это отдельная нерешённая задача.
2. Проверки блокируют установку **нового** DNAT. Старые nft map/conntrack записи
   имеют собственный lifecycle и не становятся безопасными только от PID gate.
   Следующий приоритет — session/per-flow authorization и тест повторного
   использования tuple после старой redirect записи; нельзя обещать отсутствие
   влияния прежнего NAT состояния на основании этой итерации.
3. Native IPv6 link-local пока отвергается: proc table не содержит нужного
   interface scope. Нечитаемая tcp6 table блокирует proof для IPv4 тоже.
   Stat parser ожидает современный 52-field Linux record; будущие форматы
   требуют явного обновления, не догадок.
4. PID registry не сбрасывается, пока не исправлен stop/join/re-init worker.
   Collision или насыщение могут отключить новые callbacks до выгрузки DLL;
   это безопасный отказ с ограничением совместимости, не универсальное решение.
5. Реальное Wine поведение IPv4-mapped owner query и SDK callback semantics
   требуют локальной проверки. Общий UDP lifecycle/reconnect/generation,
   полный TCP lifecycle и coexistence с VPN остаются в roadmap.

Код и тесты этой итерации готовы к review; универсальная игровая совместимость
по-прежнему не заявляется. Следующая работа начинается с пункта 2, затем
shared-fd attribution и безопасного worker lifecycle.
