# ProxyGate

Аналог Proxifier для macOS. Он перенаправляет TCP-соединения **всех** приложений, включая CLI-утилиты (codex, uv, curl, git…), через HTTPS/SOCKS5/SOCKS4-прокси или цепочки прокси. Куда направить соединение, решают правила.

## Установка

```bash
./install.sh                    # сборка + установка в /Applications + запуск
./install.sh --uninstall        # удалить приложение и хелпер
```

Только сборка, без установки: `./scripts/build-app.sh` → `build/ProxyGate.app`.

При первом запуске нажмите **Install Helper**: система один раз попросит пароль администратора. Хелпер (`proxygate-engine`) ставится как LaunchDaemon, потому что управлять pf может только root.

Дальше: **Proxies → Add…** (первый добавленный прокси становится действием правила Default), при необходимости **Rules**, затем ▶ (⌘R).

## Как это работает

```
приложение ──TCP──▶ pf: route-to lo0 + rdr ──▶ proxygate-engine (127.0.0.1:18765, root)
                                                  │ DIOCNATLOOK  → исходный адрес назначения
                                                  │ libproc      → PID/приложение по сокету
                                                  │ TLS SNI / HTTP Host → имя хоста
                                                  │ правила      → Direct / Block / Proxy / Chain
                                                  ▼
                              исходящие соединения с портов 40000–48999 (pf их пропускает)
```

- Правила проверяются сверху вниз, срабатывает первое подходящее; Default всегда последнее.
- **Applications**: имя процесса, имя `.app`, bundle id, путь, поддерживаются `*` и `?`. Правило «Google Chrome» срабатывает и на его Helper-процессы.
- **Target hosts**: `*.example.com`, `192.168.*.*`, `10.0.0.0-10.255.255.255`, `10.0.0.0/8`.
- Соединения с самими прокси-серверами всегда идут напрямую.
- Если GUI закрыть или он упадёт, хелпер сразу снимает правила pf, и трафик не останется перенаправленным в никуда.

## Ограничения

- Перехватывается только TCP. UDP и DNS идут напрямую. QUIC (UDP 443) по умолчанию блокируется, и браузеры переходят на TCP (Advanced).
- Имя хоста берётся из SNI или Host. Если клиент первым ничего не отправляет (SSH, SMTP), правила видят только IP.
- Пароли прокси хранятся в `~/Library/Application Support/ProxyGate/profiles.json` (режим 0600).
- Лог хелпера: `/var/log/proxygate-engine.log`.

## Разработка

```bash
swift test                                     # правила, SNI, pf, рукопожатия HTTPS/SOCKS5/SOCKS4, цепочки
sudo .build/debug/proxygate-engine --socket /tmp/pg.sock   # движок вручную
PROXYGATE_SOCKET=/tmp/pg.sock .build/debug/ProxyGate
```

Удаление: Advanced → Uninstall Helper.
