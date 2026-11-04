# Итерация: разрешение DNAT для конкретного TCP-пакета

База: `be37b1a1a5f2b37f2f1f0e357d8dccfc464bb01b`.
Цель — Arch Linux x86_64, ветка `arch-linux-hardening`, PR #1.
Область изменения — новые решения DNAT из nft map. Существующий conntrack
lifecycle и общая игровая совместимость этим изменением не закрыты.

## Подтверждённая проблема

Серьёзность: **High**, непредусмотренное перенаправление нового соединения.
В прежнем `backend/nft-setup.sh` цепочка `output_nat` использовала exact tuple
map независимо от результата текущего callback. `nft_arm_tcp_redirect()`
оставляет запись на 10 секунд. Следующее свежее соединение с тем же tuple
могло получить старое перенаправление при отсутствующем helper, пропуске
callback или неизменённом ответе. UID/starttime revalidation перед установкой
новой записи не защищает от уже существующей записи.

Это воспроизведено в одноразовых namespaces: заранее созданный exact map
перенаправил новый loopback connect без helper. Регрессия нового harness на
исходном nft-setup завершилась ожидаемым FAIL: `PROXY:ping` вместо
`ORIGINAL:ping`. Отдельный исходный эксперимент подтвердил обе IP families;
автоматический red-прогон остановился на первом IPv4 FAIL.

## Минимальное исправление

- `backend/nfq_verdict.{c,h}` выделяет bounded кодирование настоящего NFQUEUE
  verdict и проверку optional priority attribute. Тестируются wire layout,
  endian, размер, unaligned caller buffer и malformed priority. Старый обычный
  verdict сохраняет прежние поля и не получает дополнительного атрибута.
- Только успешный `nft_arm_tcp_redirect()` разрешает helper отправить
  `NFQA_PRIORITY` с bit31 (`0x80000000`) для текущего SYN. Ошибка, timeout,
  отсутствие shim, NO_HANDLER, UNCHANGED и недопустимая mutation его не выдают.
- Queue chain снимает bit до early accept/bypass в настроенном UID/destination
  scope. NAT требует тот же scope и этот bit, снимает его **до** map lookup
  и DNAT. Заранее выставленный SO_PRIORITY не создаёт разрешение.
- Output filter hook -99 снимает остаток, если NAT chain пропущена из-за
  существующего conntrack binding. Другие 31 priority bits сохраняются.
  Вне настроенного scope приоритет не меняется и map не используется.
- `NFQA_MARK` не записывается: изменение fwmark заставило бы NFQUEUE
  пересчитать маршрут до следующего hook. Выделенный priority bit избегает
  этого дополнительного вмешательства в policy routing.

Новых библиотек и переписывания языка нет. TCP callback ABI и IPC protocol
не изменены. Native helper и nft rules нужно обновлять вместе: остановить
runner, удалить его старую таблицу и запустить обновлённый runner. Новый helper
со старой таблицей не обеспечивает новый барьер.

## Проверки и воспроизведение

Локальные результаты и причины SKIP сохранены в evidence:

- L1: **48 групп PASS, 0 FAIL, 2 SKIP**, включая ASan/UBSan, cppcheck,
  GCC analyzer, native/PE builds и mock IPC. Два SKIP — отдельные L2 и L3.
- L2: **7 групп PASS, 0 FAIL, 1 SKIP**; целевой harness — **20/20 PASS**.
  SKIP — IPC negative tests, которым нужны sudo и несколько mapped UIDs;
  single-UID user namespace их не предоставляет. Остальные IPC hostile-input,
  lifecycle, IPv4/IPv6 TCP и ограниченные UDP проверки выполнены.

- [L1 JSON](evidence/nat-iteration-cloud.json),
  [L1 summary](evidence/nat-iteration-cloud.txt).
- [Полный L2 прогон](evidence/nat-iteration-isolated.txt).
- [Ожидаемый baseline FAIL](evidence/nat-baseline-red.txt),
  [20 целевых сетевых probes](evidence/nat-authorization-green.txt).

Целевые probes проверяют IPv4/IPv6: loopback bypass, forged priority,
отсутствие helper, отсутствие аутентифицированного shim, synthetic
UNCHANGED/NO_HANDLER/invalid/valid callbacks. Успешный callback проверяет
настоящий PID клиента, proxy echo, original getpeername и обратную трансляцию.
Четыре дополнительных probes проверяют сохранение полного priority вне scope.
Во всех случаях контролируются SO_MARK, нижние priority bits и cleanup.
Это synthetic callback provider, не решение настоящего ExitLag.

При первом полном L2 прогоне старый IPv6 assertion искал map непосредственно
в `output_nat`; правило перенесено в `tcp_authorized_nat`. Реальный redirect,
original peer и отрицательные проверки прошли. Assertion обновлён: проверяются
dispatch в новую цепочку и наличие IPv6 map в ней; затем повторён весь прогон.
Ожидаемый результат перенаправления не менялся.
Сохранён [первоначальный IPv6 FAIL](evidence/nat-iteration-initial-ipv6.txt).

На Arch с установленными зависимостями:

```sh
make -C backend
make -C backend check-nfq-verdict
bash tests/run-cloud.sh --sanitizers
bash tests/run-isolated.sh
```

L1 не требует root, игры или аккаунта. L2 сам создаёт user/network/PID/mount
namespaces и локальных peers; недоступные capabilities дают SKIP 77. В Cloud
nft установлен в отдельный test prefix, поэтому L2 helper собирался с
compile-time `EXL_NFT_PATH`; обычная release-сборка восстановлена после L2.
Общий host firewall не менялся. Native Cloud host — Debian 13.6, kernel
6.18.57; Arch CI проверяется отдельно после публикации, не подразумевается
на основании локальных прогонов.

## Остаточные риски и точка продолжения

1. **Cached conntrack DNAT не отзывается.** Старое established соединение,
   tuple reuse при существующем binding и позднее разрешение после null binding
   требуют отдельной политики и тестов. Очистка nft table не очищает conntrack.
   Отдельный cleanup path при null binding не покрыт этим fresh-tuple harness.
2. Bit31 priority зарезервирован для SYN в scope. Custom tc classids/QoS с этим
   bit несовместимы без дополнительного механизма сохранения. Другие priority
   bits и fwmark проверены; произвольные VPN/firewall chains между hooks,
   NetworkManager и systemd-resolved этим не сертифицированы.
3. Process revalidation остаётся best effort: fd может закрыться после проверки,
   same-UID exec не меняет starttime, shared-fd PID ranking ещё открыт.
4. Синхронный callback, полный queue, зависший nft subprocess и shim worker
   lifecycle остаются в roadmap. Новых performance claims нет: benchmark этой
   итерации не выполнялся.
5. Настоящий ExitLag, реле, игры и anti-cheat — **NOT TESTED**. Общий UDP,
   IPv6 extension headers/link-local и live Wine compatibility не расширялись.

Следующий приоритет: воспроизвести tuple reuse с настоящим прежним conntrack
binding, определить безопасное владение и адресную очистку project-owned flows
без flush чужого conntrack. Затем — shared-fd attribution и worker stop/join.
