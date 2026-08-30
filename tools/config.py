#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml


TIMEOUT_RE = re.compile(r"^[1-9][0-9]*(ms|s|m|h)$")
SIZE_RE = re.compile(r"^[1-9][0-9]*[kKmMgG]?$" )
EXAMPLE_IP = "203.0.113.10"
DNS_SERVER_SLOTS_PER_RESOLVER = 4
DNS_RESOLVERS = (
    ("system", "whatsapp_dns_system"),
    ("cloudflare", "whatsapp_dns_cloudflare"),
    ("google", "whatsapp_dns_google"),
)
ROUTE_BACKENDS = ("chat", "media")
SOCKS4_LOOPBACK_HOST = "127.0.0.1"


def load_config(path: str) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    if not isinstance(data, dict):
        raise ValueError("configuration root must be a mapping")
    return data


def get_path(config: dict[str, Any], path: str) -> Any:
    value: Any = config
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            raise ValueError(f"missing configuration key: {path}")
        value = value[part]
    return value


def need_int(config: dict[str, Any], path: str, minimum: int = 1, maximum: int | None = None) -> int:
    value = get_path(config, path)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{path} must be an integer")
    if value < minimum or (maximum is not None and value > maximum):
        raise ValueError(f"{path} is outside the allowed range")
    return value


def get_backend_route(config: dict[str, Any], backend: str) -> dict[str, Any]:
    if backend not in ROUTE_BACKENDS:
        raise ValueError(f"unsupported backend route: {backend}")
    if "routes" not in config:
        return {"mode": "direct"}
    routes = config["routes"]
    if not isinstance(routes, dict):
        raise ValueError("routes must be a mapping")
    if backend not in routes:
        return {"mode": "direct"}
    route = routes[backend]
    if not isinstance(route, dict):
        raise ValueError(f"routes.{backend} must be a mapping")
    return route


def validate_routes(config: dict[str, Any]) -> None:
    if "routes" not in config:
        return
    routes = config["routes"]
    if not isinstance(routes, dict):
        raise ValueError("routes must be a mapping")

    unknown_backends = [str(key) for key in routes if key not in ROUTE_BACKENDS]
    if unknown_backends:
        raise ValueError(f"routes contains unsupported backends: {', '.join(unknown_backends)}")

    for backend in ROUTE_BACKENDS:
        if backend not in routes:
            continue
        route = get_backend_route(config, backend)
        unknown_route_keys = [str(key) for key in route if key not in {"mode", "socks4"}]
        if unknown_route_keys:
            raise ValueError(
                f"routes.{backend} contains unsupported keys: {', '.join(unknown_route_keys)}"
            )
        if "mode" not in route:
            raise ValueError(f"routes.{backend}.mode is required")
        mode = route["mode"]
        if not isinstance(mode, str) or mode not in {"direct", "socks4"}:
            raise ValueError(f"routes.{backend}.mode must be direct or socks4")

        if mode == "direct":
            if "socks4" in route:
                raise ValueError(f"routes.{backend}.socks4 is only valid in socks4 mode")
            continue

        if "socks4" not in route:
            raise ValueError(f"routes.{backend}.socks4 is required in socks4 mode")
        socks4 = route["socks4"]
        if not isinstance(socks4, dict):
            raise ValueError(f"routes.{backend}.socks4 must be a mapping")
        missing_socks4_keys = [key for key in ("host", "port") if key not in socks4]
        if missing_socks4_keys:
            raise ValueError(
                f"routes.{backend}.socks4 is missing keys: {', '.join(missing_socks4_keys)}"
            )
        unknown_socks4_keys = [str(key) for key in socks4 if key not in {"host", "port"}]
        if unknown_socks4_keys:
            raise ValueError(
                f"routes.{backend}.socks4 contains unsupported keys: "
                f"{', '.join(unknown_socks4_keys)}"
            )
        if socks4["host"] != SOCKS4_LOOPBACK_HOST:
            raise ValueError(
                f"routes.{backend}.socks4.host must be exactly {SOCKS4_LOOPBACK_HOST}"
            )
        port = socks4["port"]
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError(f"routes.{backend}.socks4.port must be an integer from 1 to 65535")

        upstream_host = str(get_path(config, f"probes.{backend}_upstream_host")).strip()
        try:
            upstream_ip = ipaddress.ip_address(upstream_host)
        except ValueError:
            pass
        else:
            if not isinstance(upstream_ip, ipaddress.IPv4Address):
                raise ValueError(
                    f"probes.{backend}_upstream_host must resolve to IPv4 in socks4 mode"
                )


def validate(config: dict[str, Any], reject_example: bool = False) -> None:
    public_ip = str(get_path(config, "server.public_ip"))
    listen_ip = str(get_path(config, "server.listen_ip"))
    pub = ipaddress.ip_address(public_ip)
    listen = ipaddress.ip_address(listen_ip)
    if pub.version != 4 or listen.version != 4:
        raise ValueError("server.public_ip and server.listen_ip must be IPv4 addresses")
    if reject_example and public_ip == EXAMPLE_IP:
        raise ValueError("replace the example server.public_ip before installation")
    if pub.is_unspecified or pub.is_loopback or pub.is_multicast:
        raise ValueError("server.public_ip must identify the externally reachable proxy")

    chat = need_int(config, "ports.chat", 1, 65535)
    media = need_int(config, "ports.media", 1, 65535)
    if chat == media:
        raise ValueError("chat and media ports must differ")

    bool_paths = ["server.manage_ufw", "certificate.regenerate_on_setup"]
    for path in bool_paths:
        if not isinstance(get_path(config, path), bool):
            raise ValueError(f"{path} must be true or false")

    cidrs = get_path(config, "access.allowed_cidrs")
    if not isinstance(cidrs, list):
        raise ValueError("access.allowed_cidrs must be a list")
    for cidr in cidrs:
        network = ipaddress.ip_network(str(cidr), strict=False)
        if network.version != 4:
            raise ValueError("only IPv4 access CIDRs are supported")

    integer_paths = [
        "limits.global_connections", "limits.global_connection_rate_per_second",
        "limits.tls_connections", "limits.tls_rate_per_second",
        "limits.chat_connections", "limits.media_connections",
        "limits.per_ip_connections", "limits.per_ip_connection_rate",
        "limits.per_ip_rate_period_seconds", "limits.backlog", "keepalive.count",
        "certificate.validity_days", "certificate.ca_validity_days",
        "probes.timeout_seconds", "probes.chat_upstream_port", "probes.media_upstream_port",
    ]
    for path in integer_paths:
        maximum = 65535 if path in {
            "probes.chat_upstream_port",
            "probes.media_upstream_port",
        } else None
        need_int(config, path, maximum=maximum)
    if need_int(config, "limits.per_ip_connections") > need_int(config, "limits.global_connections"):
        raise ValueError("per-IP connection limit cannot exceed the global limit")

    for path in [
        "timeouts.connect", "timeouts.check", "timeouts.queue", "timeouts.client",
        "timeouts.server", "timeouts.client_fin", "timeouts.server_fin",
        "keepalive.idle", "keepalive.interval", "limits.stick_table_expire",
    ]:
        if not TIMEOUT_RE.fullmatch(str(get_path(config, path))):
            raise ValueError(f"invalid timeout value at {path}")
    if not SIZE_RE.fullmatch(str(get_path(config, "limits.stick_table_size"))):
        raise ValueError("invalid limits.stick_table_size")

    dns_names = get_path(config, "certificate.dns_names")
    if not isinstance(dns_names, list) or any(not isinstance(item, str) or not item for item in dns_names):
        raise ValueError("certificate.dns_names must be a list of non-empty strings")
    for path in ["probes.admin_socket", "probes.chat_upstream_host", "probes.media_upstream_host"]:
        if not str(get_path(config, path)).strip():
            raise ValueError(f"{path} cannot be empty")
    validate_routes(config)


def uses_runtime_dns(host: Any) -> bool:
    try:
        ipaddress.ip_address(str(host))
    except ValueError:
        return True
    return False


def render_backend_servers(name: str, host: Any, port: Any) -> list[str]:
    if not uses_runtime_dns(host):
        return [f"    server {name} {host}:{port}"]
    return [
        (
            f"    server-template {name}_{view} {DNS_SERVER_SLOTS_PER_RESOLVER} {host}:{port}"
            f" resolvers {resolver} resolve-prefer ipv4"
            " resolve-opts prevent-dup-ip init-addr last,none"
        )
        for view, resolver in DNS_RESOLVERS
    ]


def render_route_server_options(config: dict[str, Any], backend: str) -> str:
    route = get_backend_route(config, backend)
    if route["mode"] == "direct":
        return ""
    socks4 = route["socks4"]
    return (
        f" socks4 {socks4['host']}:{socks4['port']}"
        " check-via-socks4"
    )


def render_haproxy(config: dict[str, Any]) -> str:
    validate(config)
    g = lambda path: get_path(config, path)
    chat_host = g("probes.chat_upstream_host")
    media_host = g("probes.media_upstream_host")
    chat_route_options = render_route_server_options(config, "chat")
    media_route_options = render_route_server_options(config, "media")
    uses_dns = uses_runtime_dns(chat_host) or uses_runtime_dns(media_host)
    resolver_lines: list[str] = []
    if uses_dns:
        resolver_lines = [
            "resolvers whatsapp_dns_system",
            "    parse-resolv-conf",
            "    resolve_retries 3",
            "    timeout resolve 5s",
            "    timeout retry 1s",
            "    hold other 30s",
            "    hold refused 30s",
            "    hold nx 30s",
            "    hold timeout 30s",
            "    hold obsolete 15m",
            "    accepted_payload_size 4096",
            "",
            "resolvers whatsapp_dns_cloudflare",
            "    nameserver cloudflare_primary 1.1.1.1:53",
            "    nameserver cloudflare_secondary 1.0.0.1:53",
            "    resolve_retries 3",
            "    timeout resolve 5s",
            "    timeout retry 1s",
            "    hold other 30s",
            "    hold refused 30s",
            "    hold nx 30s",
            "    hold timeout 30s",
            "    hold obsolete 15m",
            "    accepted_payload_size 4096",
            "",
            "resolvers whatsapp_dns_google",
            "    nameserver google_primary 8.8.8.8:53",
            "    nameserver google_secondary 8.8.4.4:53",
            "    resolve_retries 3",
            "    timeout resolve 5s",
            "    timeout retry 1s",
            "    hold other 30s",
            "    hold refused 30s",
            "    hold nx 30s",
            "    hold timeout 30s",
            "    hold obsolete 15m",
            "    accepted_payload_size 4096",
            "",
        ]
    cidrs = g("access.allowed_cidrs")
    access_lines: list[str] = []
    if cidrs:
        access_lines = [
            f"    acl allowed_client src {' '.join(str(item) for item in cidrs)}",
            "    tcp-request connection reject if !allowed_client",
        ]

    common_frontend = access_lines + [
        "    tcp-request connection track-sc0 src table abuse_table",
        f"    tcp-request connection reject if {{ sc0_conn_cur gt {g('limits.per_ip_connections')} }}",
        f"    tcp-request connection reject if {{ sc0_conn_rate gt {g('limits.per_ip_connection_rate')} }}",
    ]
    lines = [
        "global",
        "    log stdout format raw local0",
        f"    maxconn {g('limits.global_connections')}",
        f"    maxconnrate {g('limits.global_connection_rate_per_second')}",
        f"    maxsslconn {g('limits.tls_connections')}",
        f"    maxsslrate {g('limits.tls_rate_per_second')}",
        "    tune.bufsize 4096",
        "    spread-checks 5",
        "    ssl-server-verify none",
        f"    stats socket {g('probes.admin_socket')} mode 660 level operator user haproxy group haproxy",
        "",
        "defaults",
        "    log global",
        "    mode tcp",
        "    option tcplog",
        "    option clitcpka",
        "    option srvtcpka",
        f"    clitcpka-idle {g('keepalive.idle')}",
        f"    clitcpka-intvl {g('keepalive.interval')}",
        f"    clitcpka-cnt {g('keepalive.count')}",
        f"    srvtcpka-idle {g('keepalive.idle')}",
        f"    srvtcpka-intvl {g('keepalive.interval')}",
        f"    srvtcpka-cnt {g('keepalive.count')}",
        f"    timeout connect {g('timeouts.connect')}",
        f"    timeout check {g('timeouts.check')}",
        f"    timeout queue {g('timeouts.queue')}",
        f"    timeout client {g('timeouts.client')}",
        f"    timeout server {g('timeouts.server')}",
        f"    timeout client-fin {g('timeouts.client_fin')}",
        f"    timeout server-fin {g('timeouts.server_fin')}",
        "",
        *resolver_lines,
        "backend abuse_table",
        f"    stick-table type ip size {g('limits.stick_table_size')} expire {g('limits.stick_table_expire')} store conn_cur,conn_rate({g('limits.per_ip_rate_period_seconds')}s)",
        "",
        "frontend whatsapp_chat_tls",
        f"    bind {g('server.listen_ip')}:{g('ports.chat')} ssl crt /etc/haproxy/ssl/proxy.whatsapp.net.pem",
        f"    maxconn {g('limits.chat_connections')}",
        f"    backlog {g('limits.backlog')}",
        *common_frontend,
        f"    tcp-request connection set-dst ipv4({g('server.public_ip')})",
        "    default_backend whatsapp_chat",
        "",
        "backend whatsapp_chat",
        "    balance leastconn",
        (
            "    default-server check inter 10s fastinter 2s downinter 30s "
            "rise 1 fall 2 observe layer4 send-proxy"
            f"{chat_route_options}"
        ),
        *render_backend_servers("g_whatsapp_net_5222", chat_host, g("probes.chat_upstream_port")),
        "",
        "frontend whatsapp_media",
        f"    bind {g('server.listen_ip')}:{g('ports.media')}",
        f"    maxconn {g('limits.media_connections')}",
        f"    backlog {g('limits.backlog')}",
        *common_frontend,
        "    default_backend whatsapp_media",
        "",
        "backend whatsapp_media",
        "    balance leastconn",
        (
            "    default-server check inter 10s fastinter 2s downinter 30s "
            "rise 1 fall 2 observe layer4"
            f"{media_route_options}"
        ),
        *render_backend_servers("whatsapp_net_443", media_host, g("probes.media_upstream_port")),
        "",
    ]
    return "\n".join(lines)


def render_openssl(config: dict[str, Any]) -> str:
    validate(config)
    public_ip = get_path(config, "server.public_ip")
    dns_names = get_path(config, "certificate.dns_names")
    alt_names = [f"IP.1 = {public_ip}"]
    alt_names.extend(f"DNS.{index} = {name}" for index, name in enumerate(dns_names, 1))
    return "\n".join([
        "[req]", "distinguished_name = req_distinguished_name", "req_extensions = v3_req",
        "prompt = no", "[req_distinguished_name]", "CN = whatsapp-proxy",
        "[v3_req]", "basicConstraints = CA:FALSE", "keyUsage = digitalSignature, keyEncipherment",
        "extendedKeyUsage = serverAuth", "subjectAltName = @alt_names", "[alt_names]",
        *alt_names, "",
    ])


def write_text(path: str, content: str) -> None:
    target = Path(path)
    target.write_text(content, encoding="utf-8", newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "render-haproxy", "openssl-config", "ports"):
        item = sub.add_parser(name)
        item.add_argument("--config", required=True)
        if name in ("render-haproxy", "openssl-config"):
            item.add_argument("--output", required=True)
        if name == "validate":
            item.add_argument("--reject-example", action="store_true")
    get_parser = sub.add_parser("get")
    get_parser.add_argument("--config", required=True)
    get_parser.add_argument("--path", required=True)
    args = parser.parse_args()

    try:
        config = load_config(args.config)
        if args.command == "validate":
            validate(config, args.reject_example)
            print("configuration is valid")
        elif args.command == "render-haproxy":
            write_text(args.output, render_haproxy(config))
        elif args.command == "openssl-config":
            write_text(args.output, render_openssl(config))
        elif args.command == "ports":
            validate(config)
            print(get_path(config, "ports.chat"))
            print(get_path(config, "ports.media"))
        elif args.command == "get":
            value = get_path(config, args.path)
            if isinstance(value, bool):
                print(str(value).lower())
            elif isinstance(value, (dict, list)):
                print(yaml.safe_dump(value, default_flow_style=True).strip())
            else:
                print(value)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
