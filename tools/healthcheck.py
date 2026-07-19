#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
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


def admin_stats(path: str, timeout: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: dict[str, Any] = {}
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(min(2.0, timeout))
                sock.connect(path)
                sock.sendall(b"show stat\n")
                chunks: list[bytes] = []
                while True:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    chunks.append(chunk)
            text = b"".join(chunks).decode("utf-8", "replace")
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
