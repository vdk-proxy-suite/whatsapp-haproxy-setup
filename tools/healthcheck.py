#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (  # noqa: E402
    get_backend_route,
    get_path,
    get_shared_443,
    load_config,
    shared_443_enabled,
    validate,
)


DNS_RESOLVER_VIEWS = ("system", "cloudflare", "google")
DNS_RESOLVER_SECTIONS = tuple(
    f"whatsapp_dns_{view}"
    for view in DNS_RESOLVER_VIEWS
)
UPSTREAM_SERVERS = (
    ("chat", "whatsapp_chat", "g_whatsapp_net_5222", "probes.chat_upstream_host"),
    ("media", "whatsapp_media", "whatsapp_net_443", "probes.media_upstream_host"),
)


class Report:
    def __init__(self, scope: str) -> None:
        self.data: dict[str, Any] = {
            "scope": scope,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "checks": [],
        }

    def check(self, name: str, action: Callable[[], Any], required: bool = True) -> None:
        started = time.monotonic()
        item: dict[str, Any] = {"name": name, "required": required}
        try:
            item["details"] = action()
            item["ok"] = True
        except Exception as exc:  # health report must retain every failure
            item["ok"] = False
            item["error"] = f"{type(exc).__name__}: {exc}"
        item["duration_ms"] = round((time.monotonic() - started) * 1000, 2)
        self.data["checks"].append(item)

    def finish(self) -> dict[str, Any]:
        self.data["ok"] = all(item["ok"] for item in self.data["checks"] if item["required"])
        return self.data


def tcp_connect(host: str, port: int, timeout: float) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        return {"peer": list(sock.getpeername()), "local": list(sock.getsockname())}


def tls_connect(host: str, port: int, sni: str, timeout: float, verify: bool) -> dict[str, Any]:
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=sni) as tls:
            der = tls.getpeercert(binary_form=True)
            cert = tls.getpeercert()
            return {
                "peer": list(tls.getpeername()),
                "tls_version": tls.version(),
                "cipher": tls.cipher()[0] if tls.cipher() else None,
                "certificate_sha256": hashlib.sha256(der).hexdigest(),
                "certificate_subject": cert.get("subject") if cert else None,
                "certificate_san": cert.get("subjectAltName") if cert else None,
            }


def resolve_ipv4_addresses(host: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not isinstance(literal, ipaddress.IPv4Address) or literal.is_unspecified:
            raise RuntimeError(f"upstream {host!r} is not a usable IPv4 address")
        return [str(literal)]

    addresses: list[str] = []
    for _family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(
        host,
        port,
        socket.AF_INET,
        socket.SOCK_STREAM,
    ):
        address = str(ipaddress.IPv4Address(sockaddr[0]))
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise RuntimeError(f"upstream {host!r} has no IPv4 address")
    return addresses


def _receive_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("SOCKS4 proxy closed the connection during handshake")
        result.extend(chunk)
    return bytes(result)


def open_socks4_tunnel(
    proxy_host: str,
    proxy_port: int,
    target_ipv4: str,
    target_port: int,
    timeout: float,
) -> tuple[socket.socket, dict[str, Any]]:
    request = (
        b"\x04\x01"
        + target_port.to_bytes(2, "big")
        + socket.inet_aton(target_ipv4)
        + b"HAProxy\x00"
    )
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(request)
        response = _receive_exact(sock, 8)
        if response[0] != 0:
            raise RuntimeError(f"invalid SOCKS4 response version: {response[0]}")
        if response[1] != 0x5A:
            raise RuntimeError(f"SOCKS4 CONNECT was rejected with code 0x{response[1]:02x}")
        return sock, {
            "mode": "socks4",
            "proxy": [proxy_host, proxy_port],
            "target": [target_ipv4, target_port],
            "reply": "granted",
        }
    except BaseException:
        sock.close()
        raise


def preflight_route(config: dict[str, Any], backend: str, timeout: float) -> dict[str, Any]:
    route = get_backend_route(config, backend)
    if route["mode"] == "direct":
        return {"mode": "direct", "preflight": "not_required"}

    upstream_host = str(get_path(config, f"probes.{backend}_upstream_host")).strip()
    upstream_port = int(get_path(config, f"probes.{backend}_upstream_port"))
    socks4 = route["socks4"]
    proxy_host = str(socks4["host"])
    proxy_port = int(socks4["port"])
    failures: list[str] = []
    addresses = resolve_ipv4_addresses(upstream_host, upstream_port)
    for address in addresses:
        tunnel: socket.socket | None = None
        try:
            tunnel, details = open_socks4_tunnel(
                proxy_host,
                proxy_port,
                address,
                upstream_port,
                timeout,
            )
            if backend == "media":
                context = ssl.create_default_context()
                with context.wrap_socket(
                    tunnel,
                    server_hostname=upstream_host.rstrip("."),
                ) as tls:
                    der = tls.getpeercert(binary_form=True)
                    details.update({
                        "tls_version": tls.version(),
                        "cipher": tls.cipher()[0] if tls.cipher() else None,
                        "certificate_sha256": hashlib.sha256(der).hexdigest(),
                    })
                    tunnel = None
            return details
        except Exception as exc:
            failures.append(f"{address}: {type(exc).__name__}: {exc}")
        finally:
            if tunnel is not None:
                tunnel.close()
    raise RuntimeError(
        f"SOCKS4 route for {backend} failed for every IPv4 candidate: "
        + "; ".join(failures)
    )


def command(args: list[str]) -> dict[str, Any]:
    result = subprocess.run(args, text=True, capture_output=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")
    return {"stdout": result.stdout.strip(), "returncode": result.returncode}


def admin_command(path: str, value: str, timeout: float) -> str:
    if not value or "\n" in value or "\r" in value:
        raise ValueError("HAProxy admin command must be one non-empty line")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect(path)
        sock.sendall((value + "\n").encode("ascii"))
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _is_template_slot(server: str, prefix: str) -> bool:
    if not server.startswith(prefix):
        return False
    suffix = server[len(prefix):]
    if suffix.isascii() and suffix.isdigit():
        return int(suffix) > 0
    for view in DNS_RESOLVER_VIEWS:
        view_prefix = f"_{view}"
        if suffix.startswith(view_prefix):
            slot = suffix[len(view_prefix):]
            return slot.isascii() and slot.isdigit() and int(slot) > 0
    return False


def _stats_upstreams(config: dict[str, Any] | None) -> list[dict[str, Any]]:
    if config is not None:
        return _configured_upstreams(config)
    return [
        {"backend": backend, "server": server, "literal": None}
        for _label, backend, server, _path in UPSTREAM_SERVERS
    ]


def inspect_admin_stats(config: dict[str, Any] | None, text: str) -> dict[str, Any]:
    rows = list(csv.DictReader(text.splitlines()))
    selected: dict[str, Any] = {}
    unavailable: list[str] = []

    for upstream in _stats_upstreams(config):
        backend = str(upstream["backend"])
        server = str(upstream["server"])
        literal = upstream["literal"]
        matched: list[dict[str, str]] = []

        for row in rows:
            px = (row.get("# pxname") or row.get("pxname") or "").lstrip("# ")
            sv = row.get("svname") or ""
            if px != backend:
                continue
            if literal is not None:
                server_matches = sv == server
            elif config is None:
                # Preserve support for reports produced by the pre-pool release.
                server_matches = sv == server or _is_template_slot(sv, server)
            else:
                server_matches = _is_template_slot(sv, server)
            if server_matches:
                matched.append(row)

        if not matched:
            mode = "static server" if literal is not None else "server-template pool"
            raise RuntimeError(f"HAProxy stats are missing {mode} {backend}/{server}")

        statuses: dict[str, dict[str, str | None]] = {}
        has_ready = False
        for row in matched:
            sv = str(row.get("svname") or "")
            status = row.get("status")
            check_status = row.get("check_status")
            statuses[sv] = {"status": status, "check_status": check_status}
            has_ready = has_ready or (
                str(status).strip() == "UP" and str(check_status).strip() == "L4OK"
            )
            selected[f"{backend}/{sv}"] = {
                "status": status,
                "check_status": check_status,
            }

        if not has_ready:
            details = ", ".join(
                f"{name}={value['status']}/{value['check_status']}"
                for name, value in statuses.items()
            )
            unavailable.append(
                f"{backend} has no ready server ({details})"
            )

    if unavailable:
        raise RuntimeError("; ".join(unavailable))
    return selected


def admin_stats(path: str, timeout: float, config: dict[str, Any] | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            text = admin_command(path, "show stat", min(2.0, timeout))
            return inspect_admin_stats(config, text)
        except Exception as exc:
            last_error = exc
        time.sleep(0.5)
    if last_error is not None:
        raise last_error
    raise RuntimeError("backend servers did not become UP before timeout")


def parse_resolver_stats(
    text: str,
    section: str = DNS_RESOLVER_SECTIONS[0],
) -> dict[str, Any]:
    section_seen = False
    in_section = False
    nameservers: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("Resolvers section "):
            if in_section and current is not None:
                nameservers.append(current)
            in_section = line.removeprefix("Resolvers section ").strip() == section
            section_seen = section_seen or in_section
            current = None
            continue
        if not in_section:
            continue
        if line.startswith("nameserver ") and line.endswith(":"):
            if current is not None:
                nameservers.append(current)
            current = {"name": line[len("nameserver "):-1].strip()}
            continue
        if current is None or ":" not in line:
            continue
        key, raw_value = (part.strip() for part in line.split(":", 1))
        if raw_value.isdigit():
            current[key] = int(raw_value)

    if current is not None:
        nameservers.append(current)
    if not section_seen:
        raise RuntimeError(f"resolver section {section!r} is absent from HAProxy runtime state")
    if not nameservers:
        raise RuntimeError(f"resolver section {section!r} has no nameservers")
    for item in nameservers:
        if "sent" not in item or "valid" not in item:
            raise RuntimeError(f"resolver nameserver counters are incomplete: {item.get('name', '<unknown>')}")

    return {
        "section": section,
        "nameserver_count": len(nameservers),
        "sent": sum(int(item["sent"]) for item in nameservers),
        "valid": sum(int(item["valid"]) for item in nameservers),
        "update": sum(int(item.get("update", 0)) for item in nameservers),
    }


def parse_server_state(text: str) -> tuple[int, list[dict[str, str]]]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("empty show servers state response")
    try:
        version = int(lines[0])
    except ValueError as exc:
        raise RuntimeError(f"invalid show servers state version: {lines[0]!r}") from exc

    header_index = next((index for index, line in enumerate(lines[1:], 1) if line.startswith("#")), None)
    if header_index is None:
        raise RuntimeError("show servers state response has no field header")
    fields = lines[header_index].lstrip("# ").split()
    required = {"be_name", "srv_name", "srv_addr", "srv_op_state", "srv_fqdn"}
    missing = sorted(required.difference(fields))
    if missing:
        raise RuntimeError(f"show servers state header is missing fields: {', '.join(missing)}")

    rows: list[dict[str, str]] = []
    for line in lines[header_index + 1:]:
        if line.startswith("#"):
            continue
        values = line.split()
        if len(values) != len(fields):
            raise RuntimeError("show servers state row does not match its field header")
        rows.append(dict(zip(fields, values)))
    return version, rows


def _configured_upstreams(config: dict[str, Any]) -> list[dict[str, Any]]:
    upstreams: list[dict[str, Any]] = []
    for label, backend, server, path in UPSTREAM_SERVERS:
        host = str(get_path(config, path)).strip()
        try:
            literal: ipaddress.IPv4Address | ipaddress.IPv6Address | None = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        upstreams.append({
            "label": label,
            "backend": backend,
            "server": server,
            "host": host,
            "literal": literal,
            "mode": "static" if literal is not None else "dns_pool",
        })
    return upstreams


def _runtime_address(raw_address: str, server: str, allow_unassigned: bool) -> ipaddress.IPv4Address | None:
    if allow_unassigned and raw_address in {"", "-", "0.0.0.0"}:
        return None
    try:
        address = ipaddress.ip_address(raw_address)
    except ValueError as exc:
        raise RuntimeError(f"HAProxy server {server} has invalid address {raw_address!r}") from exc
    if not isinstance(address, ipaddress.IPv4Address) or address.is_unspecified:
        raise RuntimeError(f"HAProxy server {server} has no usable IPv4 address")
    return address


def inspect_runtime_dns(
    config: dict[str, Any],
    resolver_texts: dict[str, str] | None,
    server_state_text: str,
) -> dict[str, Any]:
    upstreams = _configured_upstreams(config)
    version, rows = parse_server_state(server_state_text)
    servers: list[dict[str, Any]] = []
    backends: dict[str, dict[str, Any]] = {}
    hostname_upstreams: set[str] = set()

    for upstream in upstreams:
        backend = str(upstream["backend"])
        server = str(upstream["server"])
        literal = upstream["literal"]
        matching_rows = [
            row for row in rows
            if row["be_name"] == backend and (
                row["srv_name"] == server if literal is not None
                else _is_template_slot(row["srv_name"], server)
            )
        ]
        if not matching_rows:
            mode = "static server" if literal is not None else "server-template pool"
            raise RuntimeError(f"HAProxy server state is missing {mode} {backend}/{server}")

        if literal is not None and not isinstance(literal, ipaddress.IPv4Address):
            raise RuntimeError(f"configured upstream {upstream['host']!r} is not an IPv4 address")

        expected_fqdn = None if literal is not None else str(upstream["host"]).rstrip(".").lower()
        if expected_fqdn is not None:
            hostname_upstreams.add(expected_fqdn)

        assigned = 0
        up = 0
        for row in matching_rows:
            key = f"{backend}/{row['srv_name']}"
            fqdn = None if row["srv_fqdn"] in {"", "-"} else row["srv_fqdn"]
            address = _runtime_address(row["srv_addr"], key, allow_unassigned=literal is None)

            if literal is not None:
                if address != literal:
                    raise RuntimeError(f"HAProxy server {key} uses {address}, expected literal {literal}")
            else:
                if fqdn is None or fqdn.rstrip(".").lower() != expected_fqdn:
                    raise RuntimeError(
                        f"HAProxy server {key} has FQDN {fqdn!r}, expected {upstream['host']!r}"
                    )
            is_assigned = address is not None
            is_up = is_assigned and row["srv_op_state"] == "2"
            assigned += int(is_assigned)
            up += int(is_up)
            servers.append({
                "backend": backend,
                "server": row["srv_name"],
                "configured_host": upstream["host"],
                "fqdn": fqdn,
                "address": str(address) if address is not None else None,
                "assigned": is_assigned,
                "operational_state": row["srv_op_state"],
            })

        if up == 0:
            raise RuntimeError(
                f"HAProxy backend {backend} has no assigned UP server: "
                f"assigned={assigned}, slots={len(matching_rows)}"
            )
        backends[backend] = {
            "mode": upstream["mode"],
            "server_prefix": server,
            "slots": len(matching_rows),
            "assigned": assigned,
            "up": up,
            "down": assigned - up,
            "unassigned": len(matching_rows) - assigned,
        }

    resolvers: dict[str, dict[str, Any]] = {}
    if hostname_upstreams:
        if resolver_texts is None:
            raise RuntimeError("HAProxy resolver states were not queried for hostname upstreams")
        expected_queries = len(hostname_upstreams)
        for section in DNS_RESOLVER_SECTIONS:
            if section not in resolver_texts:
                raise RuntimeError(f"HAProxy resolver state was not queried for section {section!r}")
            resolver = parse_resolver_stats(resolver_texts[section], section)
            if int(resolver["sent"]) < expected_queries or int(resolver["valid"]) < expected_queries:
                raise RuntimeError(
                    f"resolver {section!r} has insufficient activity for "
                    f"{expected_queries} hostname upstream(s): "
                    f"sent={resolver['sent']}, valid={resolver['valid']}"
                )
            resolver["hostname_upstreams"] = sorted(hostname_upstreams)
            resolvers[section] = resolver

    return {
        "server_state_version": version,
        "resolvers": resolvers,
        "backends": backends,
        "servers": servers,
    }


def runtime_dns_state(config: dict[str, Any], path: str, timeout: float) -> dict[str, Any]:
    upstreams = _configured_upstreams(config)
    has_hostname = any(item["literal"] is None for item in upstreams)
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            command_timeout = min(2.0, timeout)
            resolver_texts = (
                {
                    section: admin_command(
                        path,
                        f"show resolvers {section}",
                        command_timeout,
                    )
                    for section in DNS_RESOLVER_SECTIONS
                }
                if has_hostname
                else None
            )
            server_state_text = admin_command(path, "show servers state", command_timeout)
            return inspect_runtime_dns(config, resolver_texts, server_state_text)
        except Exception as exc:
            last_error = exc
        time.sleep(0.5)
    if last_error is not None:
        raise last_error
    raise RuntimeError("HAProxy runtime DNS state did not become ready before timeout")


def limit_smoke(host: str, port: int, count: int, timeout: float) -> dict[str, Any]:
    held: list[socket.socket] = []
    try:
        for _ in range(count):
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(0.25)
            held.append(sock)
        extra = socket.create_connection((host, port), timeout=timeout)
        extra.settimeout(1.0)
        try:
            data = extra.recv(1)
            rejected = data == b""
        except (ConnectionResetError, ConnectionAbortedError):
            rejected = True
        except socket.timeout:
            rejected = False
        finally:
            extra.close()
        if not rejected:
            raise RuntimeError("the connection above the per-IP limit was not immediately rejected")
        return {"held_connections": count, "extra_connection_rejected": True}
    finally:
        for sock in held:
            sock.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=("vm", "e2e", "limits", "routes"), required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--host")
    parser.add_argument("--json-out")
    args = parser.parse_args()
    config = load_config(args.config)
    validate(config)
    g = lambda path: get_path(config, path)
    timeout = float(g("probes.timeout_seconds"))
    readiness_timeout = max(30.0, timeout * 4)
    target = args.host or str(g("server.public_ip"))
    chat_sni = str(g("server.public_ip"))
    report = Report(args.scope)

    if args.scope == "vm":
        report.check("haproxy_config", lambda: command(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"]))
        report.check("service_active", lambda: command(["systemctl", "is-active", "haproxy.service"]))
        report.check("service_enabled", lambda: command(["systemctl", "is-enabled", "haproxy.service"]))
        report.check(
            "backend_stats",
            lambda: admin_stats(str(g("probes.admin_socket")), readiness_timeout, config),
        )
        report.check(
            "backend_runtime_dns",
            lambda: runtime_dns_state(config, str(g("probes.admin_socket")), readiness_timeout),
        )
        report.check("local_chat_tls", lambda: tls_connect("127.0.0.1", int(g("ports.chat")), chat_sni, timeout, False))
        report.check("local_media_tls", lambda: tls_connect("127.0.0.1", int(g("ports.media")), str(g("probes.media_upstream_host")), timeout, True))
        if shared_443_enabled(config):
            shared_media_sni = str(get_shared_443(config)["probe_sni"])
            report.check(
                "local_media_shared_443",
                lambda: tls_connect(
                    "127.0.0.1",
                    int(g("ports.chat")),
                    shared_media_sni,
                    timeout,
                    True,
                ),
            )
    elif args.scope == "e2e":
        report.check("proxy_chat_tls", lambda: tls_connect(target, int(g("ports.chat")), chat_sni, timeout, False))
        report.check("proxy_media_tls", lambda: tls_connect(target, int(g("ports.media")), str(g("probes.media_upstream_host")), timeout, True))
        if shared_443_enabled(config):
            shared_media_sni = str(get_shared_443(config)["probe_sni"])
            report.check(
                "proxy_media_shared_443",
                lambda: tls_connect(
                    target,
                    int(g("ports.chat")),
                    shared_media_sni,
                    timeout,
                    True,
                ),
            )
    elif args.scope == "limits":
        report.check("per_ip_connection_limit", lambda: limit_smoke(target, int(g("ports.chat")), int(g("limits.per_ip_connections")), timeout), required=False)
    else:
        for backend in ("chat", "media"):
            report.check(
                f"route_{backend}",
                lambda backend=backend: preflight_route(config, backend, timeout),
            )

    result = report.finish()
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.json_out:
        Path(args.json_out).write_text(rendered + "\n", encoding="utf-8", newline="\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
