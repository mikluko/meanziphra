# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.2] - 2026-10-10

### Changed

- Добавлено и удалено доменов по категориям:

  ```text
  banks:      +3 / -0
  gov:        +5 / -3
  industry:   +2 / -1
  internet:  +20 / -1
  other:      +9 / -2
  telecom:    +1 / -0
  transport:  +0 / -3
  ```

## [0.5.1] - 2026-10-09

### Changed

- В категорию `banks` добавлено 2 домена, удалённых доменов нет.
- В категорию `gov` добавлен 1 домен, удалено 3 домена.
- В категорию `internet` добавлено 10 доменов, удалён 1 домен.
- Из категории `marketplaces` удалён 1 домен, добавленных доменов нет.
- Из категории `other` удалено 6 доменов, добавленных доменов нет.

## [0.5.0] - 2026-10-08

### Added

- Релиз снова публикует готовые бандлы со всеми категориями: `meanziphra-macos.zip`, `meanziphra-linux.zip` и `meanziphra.mobileconfig`.
- `mz bundle -target ios` собирает профиль конфигурации `meanziphra.mobileconfig` для iPhone и iPad.

## [0.4.0] - 2026-10-08

### Added

- Поддержка Linux: `mz install` ставит якорь и кросс-сертификат в системное хранилище (`update-ca-certificates` или `update-ca-trust`) и в базу NSS `~/.pki/nssdb`, `mz uninstall` удаляет их.
- `mz bundle -target linux` собирает бандл для Linux с одним кросс-сертификатом на все выбранные категории.
- Релиз публикует `mz-linux-arm64` и `mz-linux-amd64`, а `install.sh` выбирает бинарник по системе.

### Security

- `mz install`, `mz bundle` и `mz issue` не запускаются, если подкачка не шифруется, и запрещают дамп памяти при падении: в macOS по `vm.swapusage`, в Linux — если каждая подкачка лежит в zram или на dm-crypt.
- **Breaking:** ключ якоря в файле (`-key <путь>` или `anchor.key`) принимается только с флагом `-insecure`, который также отключает проверку подкачки; `op://` разрешён как прежде.

### Fixed

- Сборка `make binaries` с тега релиза совпадает с бинарником релиза: релиз собирается после того, как поставлен тег, и вшивает ту же версию модуля.

## [0.3.0] - 2026-10-08

### Added

- Программа `mz`: `mz install <категория>…` выпускает якорь и кросс-сертификаты на вашем Mac и ставит их, `mz uninstall` удаляет.
- `mz bundle -o <каталог> <категория>…` собирает бандл с `install.sh` и `uninstall.sh`, который ставится на другом Mac без сети.
- Флаг `-key` хранит ключ якоря в файле или в 1Password, чтобы обновлять категории без нового доверия; по умолчанию ключ эфемерный.
- Сборка `mz` воспроизводима: `make binaries` на том же коммите даёт побайтно тот же бинарник, что в релизе.

### Changed

- **Breaking:** релиз публикует `mz-darwin-arm64`, `mz-darwin-amd64`, `install.sh` и `uninstall.sh` вместо готовых `anchor.crt` и `cat-<категория>.crt`; `install.sh` скачивает `mz` и запускает `mz install`.
- **Breaking:** `install -only banks,gov` заменён на `mz install banks gov`; команды сопровождения запускаются как `go run ./cmd/mz -c config.release.yaml <команда>`.

## [0.2.1] - 2026-10-08

### Changed

- В категорию `industry` добавлен 1 домен, удалённых доменов нет.
- В категорию `internet` добавлено 5 доменов, удалённых доменов нет.
- Из категории `other` удалён 1 домен, добавленных доменов нет.

## [0.2.0] - 2026-10-08

### Added

- Релиз публикует `install.sh` и `uninstall.sh`: установка категорий одной командой `curl … | bash -s -- <категория>…` и удаление всех сертификатов якоря.

## [0.1.1] - 2026-10-08

### Security

- Обновлён модуль `golang.org/x/crypto` до v0.56.0, закрывающий уязвимости CVE-2026-46597 и CVE-2026-39828.

## [0.1.0] - 2026-10-08

### Changed

- В категорию `banks` добавлен 1 домен, удалённых доменов нет.

### Added

- Команды `fetch`, `update`, `issue`, `check`, `install` и `uninstall`.
- `update` берёт домены из журналов Certificate Transparency НУЦ и раскладывает их по категориям с помощью модели Jev.
- Категории `banks`, `gov`, `telecom`, `marketplaces`, `internet`, `transport`, `industry` и `other`; свои категории задаются в конфиге.
- `install -only` ставит только выбранные категории.
- Якорь ограничен зонами доменов всех категорий, например `ru`, `su` и `xn--p1ai`.
- Категория больше 1000 доменов выпускается несколькими кросс-сертификатами в одном файле: macOS отвергает сертификат больше чем с 1023 ограничениями.
- Ключ якоря задаётся в `anchor.key` путём к файлу, ссылкой `file://` или `op://`; без `anchor.key` ключ эфемерный.
- Релиз публикует `anchor.crt` и `cat-<категория>.crt`, выпущенные с эфемерным ключом, с аттестацией сборки.
- `config.example.yaml` описывает все поля конфига.

[Unreleased]: https://github.com/mikluko/meanziphra/compare/v0.5.2...HEAD
[0.5.2]: https://github.com/mikluko/meanziphra/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/mikluko/meanziphra/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/mikluko/meanziphra/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/mikluko/meanziphra/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mikluko/meanziphra/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mikluko/meanziphra/compare/v0.2.0%2B20261008...v0.2.1
[0.2.0]: https://github.com/mikluko/meanziphra/compare/v0.1.1%2B20261008...v0.2.0%2B20261008
[0.1.1]: https://github.com/mikluko/meanziphra/compare/v0.1.0%2B20261008...v0.1.1%2B20261008
[0.1.0]: https://github.com/mikluko/meanziphra/releases/tag/v0.1.0%2B20261008
