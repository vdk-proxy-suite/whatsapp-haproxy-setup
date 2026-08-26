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
from config import get_path, load_config, validate  # noqa: E402


DNS_RESOLVER_SECTION = "whatsapp_dns"
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


def admin_stats(path: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            text = admin_command(path, "show stat", min(2.0, timeout))
            rows = list(csv.DictReader(text.splitlines()))
            selected = {}
            for row in rows:
                px = (row.get("# pxname") or row.get("pxname") or "").lstrip("# ")
                sv = row.get("svname") or ""
                if (px, sv) in {
                    ("whatsapp_chat", "g_whatsapp_net_5222"),
                    ("whatsapp_media", "whatsapp_net_443"),
                }:
                    selected[f"{px}/{sv}"] = {"status": row.get("status"), "check_status": row.get("check_status")}
            last = selected
            if len(selected) == 2 and all(str(value["status"]).startswith("UP") for value in selected.values()):
                return selected
        except Exception as exc:
            last_error = exc
        time.sleep(0.5)
    if last_error and not last:
        raise last_error
    raise RuntimeError(f"backend servers are not both UP: {last}")


def parse_resolver_stats(text: str, section: str = DNS_RESOLVER_SECTION) -> dict[str, Any]:
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
        })
    return upstreams


def inspect_runtime_dns(
    config: dict[str, Any], resolver_text: str | None, server_state_text: str,
) -> dict[str, Any]:
    upstreams = _configured_upstreams(config)
    version, rows = parse_server_state(server_state_text)
    indexed = {(row["be_name"], row["srv_name"]): row for row in rows}
    servers: list[dict[str, Any]] = []
    hostname_upstreams: set[str] = set()

    for upstream in upstreams:
        key = (str(upstream["backend"]), str(upstream["server"]))
        if key not in indexed:
            raise RuntimeError(f"HAProxy server state is missing {key[0]}/{key[1]}")
        row = indexed[key]
        raw_address = row["srv_addr"]
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise RuntimeError(f"HAProxy server {key[0]}/{key[1]} has invalid address {raw_address!r}") from exc
        if not isinstance(address, ipaddress.IPv4Address) or address.is_unspecified:
            raise RuntimeError(f"HAProxy server {key[0]}/{key[1]} has no usable IPv4 address")

        literal = upstream["literal"]
        fqdn = None if row["srv_fqdn"] in {"", "-"} else row["srv_fqdn"]
        if literal is not None:
            if not isinstance(literal, ipaddress.IPv4Address):
                raise RuntimeError(f"configured upstream {upstream['host']!r} is not an IPv4 address")
            if address != literal:
                raise RuntimeError(
                    f"HAProxy server {key[0]}/{key[1]} uses {address}, expected literal {literal}"
                )
        else:
            expected_fqdn = str(upstream["host"]).rstrip(".").lower()
            if fqdn is None or fqdn.rstrip(".").lower() != expected_fqdn:
                raise RuntimeError(
                    f"HAProxy server {key[0]}/{key[1]} has FQDN {fqdn!r}, expected {upstream['host']!r}"
                )
            hostname_upstreams.add(expected_fqdn)

        servers.append({
            "backend": key[0],
            "server": key[1],
            "configured_host": upstream["host"],
            "fqdn": fqdn,
            "address": str(address),
            "operational_state": row["srv_op_state"],
        })

    resolver: dict[str, Any]
    if hostname_upstreams:
        if resolver_text is None:
            raise RuntimeError("HAProxy resolver state was not queried for hostname upstreams")
        resolver = parse_resolver_stats(resolver_text)
        expected_queries = len(hostname_upstreams)
        if int(resolver["sent"]) < expected_queries or int(resolver["valid"]) < expected_queries:
            raise RuntimeError(
                f"resolver {DNS_RESOLVER_SECTION!r} has insufficient activity for "
                f"{expected_queries} hostname upstream(s): sent={resolver['sent']}, valid={resolver['valid']}"
            )
        resolver["hostname_upstreams"] = sorted(hostname_upstreams)
    else:
        resolver = {
            "section": DNS_RESOLVER_SECTION,
            "hostname_upstreams": [],
            "skipped": "all configured upstreams are literal IPv4 addresses",
        }

    return {"server_state_version": version, "resolver": resolver, "servers": servers}


def runtime_dns_state(config: dict[str, Any], path: str, timeout: float) -> dict[str, Any]:
    upstreams = _configured_upstreams(config)
    has_hostname = any(item["literal"] is None for item in upstreams)
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            command_timeout = min(2.0, timeout)
            resolver_text = (
                admin_command(path, f"show resolvers {DNS_RESOLVER_SECTION}", command_timeout)
                if has_hostname else None
            )
            server_state_text = admin_command(path, "show servers state", command_timeout)
            return inspect_runtime_dns(config, resolver_text, server_state_text)
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
    parser.add_argument("--scope", choices=("vm", "e2e", "limits"), required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--host")
    parser.add_argument("--json-out")
    args = parser.parse_args()
    config = load_config(args.config)
    validate(config)
    g = lambda path: get_path(config, path)
    timeout = float(g("probes.timeout_seconds"))
    target = args.host or str(g("server.public_ip"))
    report = Report(args.scope)

    if args.scope == "vm":
        report.check("haproxy_config", lambda: command(["haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"]))
        report.check("service_active", lambda: command(["systemctl", "is-active", "haproxy.service"]))
        report.check("service_enabled", lambda: command(["systemctl", "is-enabled", "haproxy.service"]))
        report.check("chat_upstream_tcp", lambda: tcp_connect(str(g("probes.chat_upstream_host")), int(g("probes.chat_upstream_port")), timeout))
        report.check("media_upstream_tls", lambda: tls_connect(str(g("probes.media_upstream_host")), int(g("probes.media_upstream_port")), str(g("probes.media_upstream_host")), timeout, True))
        report.check("local_chat_tls", lambda: tls_connect("127.0.0.1", int(g("ports.chat")), target, timeout, False))
        report.check("local_media_tls", lambda: tls_connect("127.0.0.1", int(g("ports.media")), str(g("probes.media_upstream_host")), timeout, True))
        report.check("backend_stats", lambda: admin_stats(str(g("probes.admin_socket")), timeout))
        report.check("backend_runtime_dns", lambda: runtime_dns_state(config, str(g("probes.admin_socket")), timeout))
    elif args.scope == "e2e":
        report.check("proxy_chat_tls", lambda: tls_connect(target, int(g("ports.chat")), target, timeout, False))
        report.check("proxy_media_tls", lambda: tls_connect(target, int(g("ports.media")), str(g("probes.media_upstream_host")), timeout, True))
    else:
        report.check("per_ip_connection_limit", lambda: limit_smoke(target, int(g("ports.chat")), int(g("limits.per_ip_connections")), timeout), required=False)

    result = report.finish()
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.json_out:
        Path(args.json_out).write_text(rendered + "\n", encoding="utf-8", newline="\n")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
