# Standalone HAProxy proxy for WhatsApp

Нативный setup для Ubuntu 24.04 без Docker. Он устанавливает HAProxy из
репозитория Ubuntu и поднимает только два публичных TCP-порта:

- `443`: TLS termination и передача chat-трафика в `g.whatsapp.net:5222` с
  корректным PROXY header
- `587`: прозрачная передача media-трафика в `whatsapp.net:443`

Схема совместима с рекомендацией официального проекта WhatsApp Proxy для
неблагоприятных сетевых условий. VoIP официальным proxy не поддерживается.

## Быстрый запуск

```bash
unzip whatsapp-haproxy-setup-standalone-1.0.2.zip
cd whatsapp-haproxy-setup
cp config.example.yaml config.yaml
nano config.yaml
chmod +x setuphaproxy.sh cleanhaproxy.sh steps/*.sh tools/*.py
sudo ./setuphaproxy.sh all
```

В `config.yaml` обязательно замените `server.public_ip`. Пустой
`access.allowed_cidrs` означает публичный беспарольный WhatsApp proxy. Это не
HTTP- и не SOCKS-прокси: направления backend зафиксированы в HAProxy.

Скрипт поддерживает отдельные шаги:

```bash
sudo ./setuphaproxy.sh 0  # диагностика, backup и остановка
sudo ./setuphaproxy.sh 1  # установка HAProxy и зависимостей
sudo ./setuphaproxy.sh 2  # сертификат и конфигурация
sudo ./setuphaproxy.sh 3  # systemd start и VM-side health-check
```

Можно хранить YAML вне распакованного каталога:

```bash
sudo ./setuphaproxy.sh all --config /secure/path/whatsapp-proxy.yaml
```

## Cloud firewall и DDoS

Setup не меняет cloud security group и не подключает DDoS-защиту. Для
публичного сервиса разрешите ingress TCP только на `443` и `587`. SSH должен
быть ограничен отдельно. VM нужен исходящий TCP к `g.whatsapp.net:5222` и
`whatsapp.net:443`; если firewall не поддерживает DNS-правила, используйте
подходящие общие egress-правила.

UFW по умолчанию не меняется. `server.manage_ufw: true` добавляет два allow
правила, но не заменяет cloud firewall.

Публичного HAProxy stats-порта нет. Диагностика использует локальный сокет
`/run/haproxy/admin.sock`.

## Проверки

На VM:

```bash
sudo python3 tools/healthcheck.py --scope vm --config config.yaml
```

С клиентской машины:

```bash
python -m venv venv
venv/bin/pip install PyYAML
venv/bin/python tools/healthcheck.py --scope e2e --config config.yaml \
  --json-out whatsapp-haproxy-e2e.json
```

Windows PowerShell использует `venv\Scripts\python.exe`. E2E выполняет TLS
handshake с самоподписанным frontend `443` и проверенный сквозной TLS handshake
до `*.whatsapp.net` через `587`. Он не эмулирует закрытый протокол WhatsApp и не
доказывает доставку сообщения в приложении.

Неблокирующая smoke-проверка per-IP лимита:

```bash
python tools/healthcheck.py --scope limits --config config.yaml
```

## Настройка WhatsApp

В приложении укажите публичный IP или DNS-имя VM, порт чата `443` и порт медиа
`587`. Сертификат на `443` создаётся локально при установке и не требует
публичного CA.

## Полная очистка

Без `--yes` cleaner всегда работает в dry-run:

```bash
./cleanhaproxy.sh
sudo ./cleanhaproxy.sh --yes
sudo ./cleanhaproxy.sh --yes --purge-package --purge-setup
```

Дополнительные флаги:

```bash
sudo ./cleanhaproxy.sh --yes --keep-backups
sudo ./cleanhaproxy.sh --yes --purge-ufw
```

Cleaner останавливает HAProxy и удаляет `/etc/haproxy`, выделенные логи,
runtime state и backup этого setup. `--purge-package` удаляет пакет
HAProxy, но намеренно не запускает глобальный `apt autoremove`. Cloud firewall
и общий systemd journal не меняются. Cleaner не затрагивает 3proxy.

## Источники

- Официальный проект: <https://github.com/WhatsApp/proxy>
- Официальная HAProxy-схема: <https://github.com/WhatsApp/proxy/blob/main/proxy/src/proxy_config.cfg>
