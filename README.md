# ExitLag Bridge — Arch Linux x86_64

**Заброшен, не поддерживается.** Экспериментальный исходник на основе
[Cheaux/exitlag-bridge](https://github.com/Cheaux/exitlag-bridge).
Нужны официальный ExitLag Windows-клиент, собственный аккаунт и подписка.
Proprietary binaries и учётные данные не включены.

В составе: Linux backend TCP/UDP IPv4/IPv6, Wine shim, Tkinter desktop,
выбор процессов, диагностика, тесты и LLVM-сборка установщика.
Реальная маршрутизация PEAK/Discord и универсальная совместимость не подтверждены.

```sh
sudo pacman -S --needed base-devel clang lld llvm bison flex m4 libmnl nftables iproute2 python tk polkit curl ca-certificates fontconfig ttf-dejavu
make -C backend
python3 installers/build_runtime.py payloads --output installers/payloads
python3 installers/linux/build.py --output build/releases
```

Установку выполняет `sudo bash install.sh` из распакованного installer;
интерфейс и Wine запускаются обычным пользователем. UDP экспериментален;
GUI не подтверждает реальный маршрут. Обновление программы само по себе
не обновляет DLL в существующем Wine prefix. Native-приложения требуют
подтверждённой Windows identity; её нельзя угадать по имени процесса.

Проверки: `bash tests/run-cloud.sh --sanitizers` без аккаунта/root;
`bash tests/run-isolated.sh` — отдельные disposable namespaces.
Для UI-тестов нужны `xorg-server-xvfb`, для static checks — `shellcheck cppcheck`.
Тесты с mock callbacks не доказывают работу через сервисное реле.

GPL-3.0-only: [LICENSE](LICENSE). Обязательные third-party notices и
неразрешённые вопросы происхождения интерфейса: [THIRD_PARTY.md](THIRD_PARTY.md).
