from __future__ import annotations

import contextlib
import csv
import os
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any


HAPROXY = shutil.which("haproxy")


def _listener(address: str = "127.0.0.1") -> socket.socket:
    result = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    result.bind((address, 0))
    result.listen(32)
    result.settimeout(0.1)
    return result


def _free_port() -> int:
    reservation = _listener()
    try:
        return int(reservation.getsockname()[1])
    finally:
        reservation.close()


def _receive_exact(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)


def _wait_until(action, description: str, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            result = action()
            if result:
                return result
        except (ConnectionError, OSError, AssertionError) as exc:
            last_error = exc
        time.sleep(0.05)
    detail = f"; last error: {last_error}" if last_error else ""
    raise AssertionError(f"timed out waiting for {description}{detail}")


class _EchoBackend:
    def __init__(self) -> None:
        self._listener = _listener("127.0.0.2")
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._accept_count = 0
        self._payloads: list[bytes] = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def accept_count(self) -> int:
        with self._lock:
            return self._accept_count

    def payloads(self) -> list[bytes]:
        with self._lock:
            return list(self._payloads)

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listener.close()
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        self._thread.join(timeout=2)

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _peer = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._accept_count += 1
                self._connections.add(connection)
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(1.0)
            payload = connection.recv(4096)
            if payload:
                with self._lock:
                    self._payloads.append(payload)
                connection.sendall(b"backend:" + payload)
        except (ConnectionError, OSError):
            pass
        finally:
            with self._lock:
                self._connections.discard(connection)
            connection.close()


class _Socks4Proxy:
    def __init__(self) -> None:
        self._listener = _listener()
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._requests: list[dict[str, Any]] = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def requests(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._requests]

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self._listener.close()
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        self._thread.join(timeout=2)

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                connection, _peer = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._connections.add(connection)
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        upstream: socket.socket | None = None
        try:
            client.settimeout(2.0)
            header = _receive_exact(client, 8)
            user_id = bytearray()
            while True:
                value = _receive_exact(client, 1)
                if value == b"\x00":
                    break
                user_id.extend(value)
                if len(user_id) > 255:
                    raise ValueError("SOCKS4 user id is too long")
            if header[0] != 4 or header[1] != 1:
                raise ValueError("unsupported SOCKS4 request")
            target_port = int.from_bytes(header[2:4], "big")
            target_host = socket.inet_ntoa(header[4:8])
            with self._lock:
                self._requests.append({
                    "host": target_host,
                    "port": target_port,
                    "user_id": bytes(user_id),
                })

            upstream = socket.create_connection((target_host, target_port), timeout=2.0)
            with self._lock:
                self._connections.add(upstream)
            client.sendall(b"\x00\x5a" + header[2:8])
            client.settimeout(None)
            upstream.settimeout(None)

            while not self._stop.is_set():
                readable, _writable, _exceptional = select.select(
                    [client, upstream],
                    [],
                    [],
                    0.1,
                )
                for source in readable:
                    payload = source.recv(4096)
                    if not payload:
                        return
                    destination = upstream if source is client else client
                    destination.sendall(payload)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            for connection in (client, upstream):
                if connection is None:
                    continue
                with self._lock:
                    self._connections.discard(connection)
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
                connection.close()


def _runtime_command(socket_path: Path, value: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2.0)
        client.connect(str(socket_path))
        client.sendall(value.encode("ascii") + b"\n")
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _server_status(socket_path: Path) -> tuple[str, str] | None:
    if not socket_path.exists():
        return None
    rows = csv.DictReader(_runtime_command(socket_path, "show stat").splitlines())
    for row in rows:
        if row.get("# pxname") == "media_backend" and row.get("svname") == "media_server":
            return str(row.get("status")), str(row.get("check_status"))
    return None


def _frontend_unavailable(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as client:
            client.settimeout(0.5)
            client.sendall(b"must-not-bypass-socks\n")
            return client.recv(1) == b""
    except (ConnectionError, OSError):
        return True


@unittest.skipUnless(os.name == "posix" and HAPROXY, "requires HAProxy on a POSIX host")
class HAProxySocks4EgressIntegrationTests(unittest.TestCase):
    def test_default_server_routes_checks_and_traffic_and_fails_closed(self) -> None:
        try:
            backend = _EchoBackend()
        except OSError as exc:
            self.skipTest(f"127.0.0.2 loopback listener is unavailable: {exc}")
        proxy = _Socks4Proxy()
        process: subprocess.Popen[str] | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="wa-haproxy-socks4-") as temporary:
                temp = Path(temporary)
                admin_socket = temp / "admin.sock"
                config_path = temp / "haproxy.cfg"
                frontend_port = _free_port()
                config_path.write_text(
                    f"""global
    stats socket {admin_socket} mode 600 level admin
    maxconn 32

defaults
    mode tcp
    timeout connect 500ms
    timeout client 5s
    timeout server 5s
    timeout check 300ms

frontend media_frontend
    bind 127.0.0.1:{frontend_port}
    default_backend media_backend

backend media_backend
    default-server check inter 200ms fastinter 100ms downinter 100ms rise 1 fall 1 socks4 127.0.0.1:{proxy.port} check-via-socks4
    server media_server 127.0.0.2:{backend.port}
""",
                    encoding="utf-8",
                    newline="\n",
                )

                validation = subprocess.run(
                    [str(HAPROXY), "-c", "-f", str(config_path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    validation.returncode,
                    0,
                    validation.stdout + validation.stderr,
                )
                process = subprocess.Popen(
                    [str(HAPROXY), "-db", "-f", str(config_path)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )

                def process_running() -> bool:
                    assert process is not None
                    if process.poll() is not None:
                        output = process.stdout.read() if process.stdout else ""
                        raise AssertionError(f"HAProxy exited with {process.returncode}: {output}")
                    return admin_socket.exists()

                _wait_until(process_running, "HAProxy runtime socket")
                _wait_until(
                    lambda: _server_status(admin_socket) == ("UP", "L4OK"),
                    "SOCKS-routed health check",
                )
                health_requests = proxy.requests()
                self.assertTrue(health_requests)
                self.assertTrue(all(item["host"] == "127.0.0.2" for item in health_requests))
                self.assertTrue(all(item["port"] == backend.port for item in health_requests))
                self.assertTrue(all(item["user_id"] == b"HAProxy" for item in health_requests))

                payload = b"media-through-socks4\n"
                with socket.create_connection(("127.0.0.1", frontend_port), timeout=2.0) as client:
                    client.settimeout(2.0)
                    client.sendall(payload)
                    self.assertEqual(
                        _receive_exact(client, len(b"backend:") + len(payload)),
                        b"backend:" + payload,
                    )
                _wait_until(
                    lambda: payload in backend.payloads(),
                    "application payload at backend through SOCKS4",
                )

                proxy.close()
                _wait_until(
                    lambda: (
                        (status := _server_status(admin_socket)) is not None
                        and status[0].startswith("DOWN")
                    ),
                    "backend to become DOWN after SOCKS4 failure",
                )
                accepted_before = backend.accept_count()
                self.assertTrue(_frontend_unavailable(frontend_port))
                time.sleep(0.4)
                self.assertEqual(
                    backend.accept_count(),
                    accepted_before,
                    "HAProxy bypassed the failed SOCKS4 route and connected directly",
                )
                self.assertIsNone(process.poll())
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
            proxy.close()
            backend.close()


if __name__ == "__main__":
    unittest.main()
