# Standalone HAProxy proxy for WhatsApp

Нативный setup для Ubuntu 24.04 без Docker. Он устанавливает HAProxy из
репозитория Ubuntu и поднимает только два публичных TCP-порта:

- `443`: TLS termination и передача chat-трафика в `g.whatsapp.net:5222` с
  корректным PROXY header
- `587`: прозрачная передача media-трафика в `whatsapp.net:443`

Схема совместима с рекомендацией официального проекта WhatsApp Proxy для
неблагоприятных сетевых условий. VoIP официальным proxy не поддерживается.

## Изменения версии 1.2.0

- DNS-upstream теперь представлен пулом из 16 независимо проверяемых IPv4:
  недоступный с VM адрес исключается из новых подключений, пока остальные
  доступные адреса продолжают обслуживать трафик
- HAProxy в течение 15 минут сохраняет ранее полученные одиночные A-records,
  поэтому последовательная DNS-ротация наполняет пул без restart или reload
- Healthcheck проверяет состояние всего runtime-пула и считает backend рабочим,
  если назначен и доступен хотя бы один адрес
- Внешняя YAML-схема не изменилась; literal IPv4 остаётся одним статическим
  upstream без DNS-ротации

## Изменения версии 1.1.0

- HAProxy переразрешает DNS-имена chat- и media-upstream в runtime и
  обновляет их IPv4-адреса без restart или reload
- Внешняя YAML-схема не изменилась: конфигурации версии 1.0.3
  продолжают работать без изменений
- TLS termination и PROXY v1 для chat `443`, raw TCP passthrough для
  media `587`, ACL, limits, timeouts и certificate lifecycle не изменились

## Изменения версии 1.0.3

- Production-профили `config.<ssh-alias>.yaml` и локальный `AGENTS.md`
  исключаются из Git и standalone ZIP
- Release builder исключает локальные окружения и runtime artifacts

## Быстрый запуск

```bash
unzip whatsapp-haproxy-setup-standalone-1.2.0.zip
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

## Runtime DNS-ротация upstream

HAProxy переразрешает `probes.chat_upstream_host` и
`probes.media_upstream_host` через DNS-серверы VM. Список nameserver
считывается из `/etc/resolv.conf` при start/reload HAProxy; если сам
список изменился, HAProxy нужно reload/restart. `/etc/hosts` в этом
маршруте не используется.

Для каждого DNS-upstream действует следующая семантика:

- Базовый интервал переразрешения — 5 секунд, когда нет другого триггера;
  connection timeout health-check может запустить его раньше. Интервал задаёт
  `timeout resolve`, а не authoritative DNS TTL и не `hold valid`
- HAProxy создаёт 16 слотов, запрещает дублирование адресов между ними и
  накапливает как одновременные, так и последовательные одиночные A-records
- Ранее замеченный адрес остаётся кандидатом 15 минут после последнего
  появления в корректном DNS-ответе. Повторное появление продлевает это окно
- Каждый назначенный адрес проверяется TCP health-check с VM. Рабочие адреса
  участвуют в `leastconn`, недоступные получают `DOWN` и исключаются из новых
  подключений. Если `UP`-адресов нет, backend закрывается без direct fallback
- Основная проверка выполняется каждые 10 секунд; переходное состояние
  перепроверяется через 2 секунды, `DOWN`-адрес — каждые 30 секунд. Для
  исключения адреса нужны две неудачи подряд, для возврата — один успех
- Смена адреса или его переход в `DOWN` не переносит и принудительно не
  разрывает уже установленные TCP-сессии. Новые сессии используют доступные
  слоты
- Внутри неудачного цикла HAProxy делает до трёх DNS-попыток с
  интервалом 1 секунда и принимает DNS-payload до 4096 байт
- При `NXDOMAIN`, `REFUSED`, timeout и других DNS-ошибках HAProxy проверяет,
  был ли valid answer за предыдущие 30 секунд. Если нет, соответствующий
  server выводится из работы до нового корректного answer; затем его
  готовность снова определяют L4 health-checks
- `init-addr last,none` не делает libc fallback. Если прежнего state нет,
  backend стартует без адреса и сам восстанавливается после успешного DNS-answer
- DNS-пул хранится в памяти процесса. После холодного restart HAProxy или VM он
  собирается заново из последующих DNS-ответов; отдельного selector-daemon и
  постоянного кэша нет

Если в upstream указан literal IPv4, HAProxy оставляет его статическим.
Для перехода на 1.2.0 не нужно добавлять ключи в `config.yaml`: все текущие
поля и их значения сохраняют прежнюю семантику.

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
- Runtime DNS HAProxy 2.8: <https://docs.haproxy.org/2.8/configuration.html#5.3.2>
- HAProxy `server-template`: <https://docs.haproxy.org/2.8/configuration.html#server-template>
