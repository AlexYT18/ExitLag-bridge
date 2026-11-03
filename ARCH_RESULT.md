# Arch Linux x86_64: результат разработки

Это исходники ExitLag Bridge после аудита и исправлений. Ветка публикации —
`arch-linux-hardening` в форке `AlexYT18/ExitLag-bridge`. Экспериментальный статус сохранён: универсальная
совместимость с играми и стабильный релиз пока не подтверждены.

- [Полный отчёт об изменениях и проверках](docs/audit/ITERATION_REPORT.md)
- [TCP attribution](docs/audit/TCP_ATTRIBUTION_ITERATION.md)
- [Текущая итерация: авторизация DNAT и точка продолжения](docs/audit/TCP_AUTHORIZATION_ITERATION.md)
- [Выбор запущенной игры без ручных Linux-путей](docs/game-selection.md)
- [Итерация интерфейса и её проверки](docs/audit/PROCESS_PICKER_ITERATION.md)
- [Начальный аудит](docs/audit/INITIAL_AUDIT.md)
- [Все 185 исходных файлов](docs/audit/FILE_INVENTORY.md)
- [Перечень изменённых файлов](docs/audit/CHANGED_FILES.md)
- [Следующие задачи и критерии приёмки](docs/audit/ROADMAP.md)

Подготовка и безопасные проверки на Arch:

```sh
sudo pacman -S --needed base-devel clang lld llvm libmnl nftables iproute2 python tk shellcheck cppcheck git
make -C backend
bash tests/run-cloud.sh --sanitizers
bash tests/run-isolated.sh
```

Первый runner выполняет проверки без root и аккаунта ExitLag. Второй создаёт
одноразовые namespaces для kernel networking; отсутствие возможностей означает
SKIP, а не успешную проверку. Архив не содержит Wine prefix, готовых installer
payloads, оригинального клиента, учётных данных или игровых captures.

Для переноса старой identity map: argv-only источники больше не принимаются.
Native map использует реальный executable; prefix map требует третью колонку
`OWNER_EXE`. Подробности и ограничения в
[process-identity-translation.md](docs/process-identity-translation.md).

Для настоящего игрового запуска дополнительно нужны официальный ExitLag,
действующая подписка, подходящий Wine и локальные испытания. Следуйте
[инструкции Arch](docs/arch-linux.md) и учитывайте открытые риски отчёта.
Не запускайте весь клиент с правами root и не принимайте synthetic redirect за
доказательство прохождения игры через реле.
