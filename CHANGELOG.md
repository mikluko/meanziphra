# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/2.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/mikluko/meanziphra/commits/main
[0.1.1]: https://github.com/mikluko/meanziphra/releases/tag/v0.1.1+20261008
[0.1.0]: https://github.com/mikluko/meanziphra/releases/tag/v0.1.0+20261008
