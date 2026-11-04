# UDP: проверенный промежуточный коммит

База: `132aec3e9ffdd10a151ad76ce0a848450875428d`. Цель — Arch Linux x86_64.
Коммит сохраняет независимо проверяемые компоненты. Он **не включает** ещё
не проверенную интеграцию multi-endpoint UDP в daemon, shim или desktop launcher.

Добавлено:

- `udp_attribution.{c,h}`: строгий lookup socket inode по local/remote tuple,
  connected/unconnected sockets, IPv4/IPv6 и явный отказ при неоднозначности.
- `udp_packet.{c,h}`: bounded parsing/building IPv4/IPv6 UDP, checksums,
  нулевые datagrams, malformed/fragment/extension policies.
- `udp_peers.{c,h}`: ограниченный reverse-peer ledger с prepare/commit после
  успешной доставки, expiration и отказом вместо вытеснения активных peers.
- `nfq_verdict_build_packet()`: bounded NFQA_PAYLOAD replacement с максимумом
  65531 bytes. Обычный verdict сохраняет прежний wire format и не пишет fwmark.
- Unit/sanitizer/static checks зарегистрированы в Arch source CI.

Нормальные и ASan/UBSan сборки четырёх targeted suites прошли:
UDP attribution — 73 cases, packet codec — 1 418 077 assertions (включая
20 000 детерминированных mutations), peer lifecycle и NFQUEUE encoding — PASS.
Assertions не являются количеством независимых игр или benchmark-результатом.

```sh
make -C backend check-udp-attribution check-udp-packet check-udp-peers check-nfq-verdict
make -C backend CFLAGS='-O1 -g -Wall -Wextra -fno-omit-frame-pointer -fsanitize=address,undefined' LDFLAGS='-fsanitize=address,undefined' check-udp-attribution check-udp-packet check-udp-peers check-nfq-verdict
```

Ограничения: IPv6 scoped/link-local/mapped wire addresses, fragments, extensions
и jumbograms не объявляются поддержанными. Для IPv4 lookup IPv6 ANY bind без
доказанного V6ONLY даёт conservative ambiguity. Проверка inode не блокирует
последующее закрытие fd; daemon обязан перепроверять process generation/UID.

Остаётся довести и выполнить integration tests нескольких endpoints,
remote/payload translation в обе стороны, reconnect/rebind и чужого трафика;
затем подключить опциональный UDP к установленному supervisor. Новый минимальный
desktop layout пока не включён в этот коммит. L2 multi-endpoint и L3 здесь
**NOT TESTED**; готовая поддержка PEAK или реле ExitLag не заявляется.
