# ExitLag Bridge — Arch Linux

Экспериментальный Linux compatibility layer для запуска официального ExitLag
через Wine с native backend для сетевого трафика.

**Этот форк развивается в сторону Arch Linux x86_64.** Основная цель — удобная,
безопасная и проверяемая работа с native Linux, Steam/Proton и Wine-играми.
Универсальная совместимость пока не подтверждена.

## На чём основан проект

За основу взят **[ExitLag Bridge от Cheaux](https://github.com/Cheaux/exitlag-bridge)**.
Исходная реализация, поддержка других платформ и прежние результаты испытаний
принадлежат исходному проекту и его участникам.

Всё прежнее описание сохранено в **[оригинальном README](docs/UPSTREAM_README.md)**
на момент базы этого форка. Также доступен
[README исходного проекта на GitHub](https://github.com/Cheaux/exitlag-bridge/blob/dfdd0ee43e2edb850fec31621e8feffa3dea2715/README.md).
Исторические результаты upstream не означают, что текущая сборка форка прошла
те же игровые проверки.

## Что уже сделано в этом форке

- Проведён аудит исходников; усилены IPC authentication, проверка владельца
  процесса и сокетов, обработка ошибок и очистка сетевого состояния.
- Доработано перенаправление TCP IPv4/IPv6 и добавлен экспериментальный
  multi-endpoint UDP IPv4/IPv6 с двусторонними синтетическими тестами.
- Исправлены остановка и повторный запуск потоков shim, timeout и очистка UDP.
- Добавлен [тёмный desktop-интерфейс](docs/desktop-ui.md) с пятью разделами,
  выбором процессов, поиском, Steam AppID и Wine/Proton prefix. Запуск/остановка
  выполняются одной кнопкой; диагностика скрывает секреты и приватные пути.
- Подготовлена сборка установщика `0.4.0+arch.2` через LLVM с проверкой ABI,
  hashes компонентов и записью source revision.

Проверки сетевой основы до обновления интерфейса: **68 PASS / 0 FAIL / 2 SKIP**.
Изолированные сетевые проверки основы: **8 PASS / 0 FAIL / 1 SKIP**.
UI проверен отдельно: 32 launcher/state/privacy, 35 picker, 16 Tk/Xvfb и
10 packaging tests. Wine/WMI bootstrap основы также проверен без аккаунта. Это не подтверждение работы
официального клиента, настоящих реле или стабильной игры.

**PEAK, Discord и другие игры в текущей сборке форка пока не проверены через
реальный ExitLag.** Проверки Arch desktop и runtime callbacks официального
клиента остаются следующим этапом. Асинхронные UDP callbacks и совместимость
с VPN/policy routing также требуют дальнейшей работы.

## Сборка и документация

- [Сборка и установка на Arch Linux](docs/arch-linux.md).
- [Результат разработки и основные инструкции](ARCH_RESULT.md).
- [Последняя итерация: изменения, проверки и ограничения](docs/audit/RELIABILITY_AND_PACKAGING_ITERATION.md).
- [Выбор игры и процесса](docs/game-selection.md).
- [Экспериментальный UDP](docs/udp-multi.md).
- [Следующая проверка: PEAK через Steam/Proton](docs/peak-validation.md).
- [План дальнейшей разработки](docs/audit/ROADMAP.md).

Основная ветка разработки — **[`main`](https://github.com/AlexYT18/ExitLag-bridge/tree/main)**.
Предыдущие этапы объединены через **[PR #1](https://github.com/AlexYT18/ExitLag-bridge/pull/1)**.
Старые установщики upstream не содержат изменений этого форка; `git pull`
не обновляет уже установленную программу.

## Лицензия и официальный сервис

Проект не связан с ExitLag и не поддерживается его разработчиками. Нужны
официальный Windows-клиент, собственный легальный аккаунт и действующая подписка.
Клиент, учётные данные и proprietary components ExitLag в репозиторий не включены.

Лицензия кода проекта — **GPL-3.0-only**. Существующие лицензии и notices
сохранены: [LICENSE](LICENSE), [THIRD_PARTY.md](THIRD_PARTY.md),
[provenance review](docs/provenance-review.md).
