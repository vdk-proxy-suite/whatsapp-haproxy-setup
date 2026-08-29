from __future__ import annotations

import contextlib
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path


HAPROXY = shutil.which("haproxy")


def _encode_dns_name(name: str) -> bytes:
    labels = name.rstrip(".").split(".")
    return b"".join(bytes((len(label),)) + label.encode("ascii") for label in labels) + b"\x00"


def _decode_dns_name(packet: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        if offset >= len(packet):
            raise ValueError("truncated DNS name")
        length = packet[offset]
        offset += 1
        if length == 0:
            return ".".join(labels).lower(), offset
        if length & 0xC0:
            raise ValueError("compressed DNS question names are not supported by the test server")
        if offset + length > len(packet):
            raise ValueError("truncated DNS label")
        labels.append(packet[offset : offset + length].decode("ascii"))
        offset += length


class _FakeDnsServer:
    CHAT_ALIAS = "g.whatsapp.test"
    CHAT_TARGET = "edge.whatsapp.test"
    MEDIA_NAME = "whatsapp.test"

    def __init__(self, initial_ip: str) -> None:
        self._lock = threading.Lock()
        self._ip = initial_ip
        self._queries: list[tuple[str, int]] = []
        self._stop = threading.Event()
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(0.1)
        self.port = int(self._socket.getsockname()[1])
        self._thread = threading.Thread(target=self._serve, name="fake-dns", daemon=True)
        self._thread.start()

    def rotate(self, address: str) -> None:
        socket.inet_aton(address)
        with self._lock:
            self._ip = address

    def queries(self) -> list[tuple[str, int]]:
        with self._lock:
            return list(self._queries)

    def close(self) -> None:
        self._stop.set()
        self._socket.close()
        self._thread.join(timeout=2)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                packet, peer = self._socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            response = self._response(packet)
            if response is None:
                continue
            try:
                self._socket.sendto(response, peer)
            except OSError:
                if not self._stop.is_set():
                    raise

    def _response(self, packet: bytes) -> bytes | None:
        if len(packet) < 12:
            return None
        try:
            name, end = _decode_dns_name(packet, 12)
            if end + 4 > len(packet):
                return None
            query_type, query_class = struct.unpack_from("!HH", packet, end)
        except (UnicodeDecodeError, ValueError):
            return None

        question = packet[12 : end + 4]
        with self._lock:
            self._queries.append((name, query_type))
            address = socket.inet_aton(self._ip)

        answers: list[bytes] = []
        if query_class == 1 and query_type in (1, 255):
            if name == self.CHAT_ALIAS:
                target = _encode_dns_name(self.CHAT_TARGET)
                answers.append(
                    b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 1, len(target)) + target
                )
                answers.append(
                    target + struct.pack("!HHIH", 1, 1, 1, len(address)) + address
                )
            elif name in (self.CHAT_TARGET, self.MEDIA_NAME):
                answers.append(
                    b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, len(address)) + address
                )

        if answers:
            flags = 0x8180  # standard recursive response, no error
        elif name in (self.CHAT_ALIAS, self.CHAT_TARGET, self.MEDIA_NAME):
            flags = 0x8180  # NODATA; allows HAProxy's A/AAAA fallback
        else:
            flags = 0x8183  # NXDOMAIN
        header = struct.pack("!HHHHHH", struct.unpack_from("!H", packet)[0], flags, 1, len(answers), 0, 0)
        return header + question + b"".join(answers)


class _BackendListener:
    def __init__(self, listener: socket.socket, marker: str, expect_proxy: bool) -> None:
        self.marker = marker.encode("ascii")
        self.expect_proxy = expect_proxy
        self._listener = listener
        self._listener.settimeout(0.1)
        self._accept_stop = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._records: list[bytes] = []
        self._connections: set[socket.socket] = set()
        self._thread = threading.Thread(target=self._accept, name=f"backend-{marker}", daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return int(self._listener.getsockname()[1])

    def records(self) -> list[bytes]:
        with self._lock:
            return list(self._records)

    def close(self) -> None:
        self.stop_accepting()
        self._stop.set()
        with self._lock:
            connections = list(self._connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()

    def stop_accepting(self) -> None:
        self._accept_stop.set()
        self._listener.close()
        self._thread.join(timeout=2)

    def _accept(self) -> None:
        while not self._accept_stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._lock:
                self._connections.add(connection)
            threading.Thread(
                target=self._handle,
                args=(connection,),
                name=f"connection-{self.marker.decode('ascii')}",
                daemon=True,
            ).start()

    def _record(self, payload: bytes) -> None:
        with self._lock:
            self._records.append(payload)

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(2)
            initial = self._read_initial(connection)
            if not initial:
                return
            self._record(initial)

            if self.expect_proxy:
                _, separator, application = initial.partition(b"\r\n")
                if not separator or not application:
                    return  # a send-proxy health check has no application payload
            connection.sendall(self.marker + b"\n")

            connection.settimeout(0.2)
            pending = bytearray()
            while not self._stop.is_set():
                try:
                    payload = connection.recv(4096)
                except socket.timeout:
                    continue
                if not payload:
                    return
                pending.extend(payload)
                while b"\n" in pending:
                    end = pending.index(b"\n") + 1
                    message = bytes(pending[:end])
                    del pending[:end]
                    self._record(message)
                    connection.sendall(self.marker + b":" + message)
        except (ConnectionError, OSError):
            return
        finally:
            with self._lock:
                self._connections.discard(connection)
            connection.close()

    def _read_initial(self, connection: socket.socket) -> bytes:
        if not self.expect_proxy:
            payload = bytearray()
            while b"\n" not in payload:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                payload.extend(chunk)
            return bytes(payload)

        payload = bytearray()
        while b"\r\n" not in payload and len(payload) < 512:
            chunk = connection.recv(512)
            if not chunk:
                return bytes(payload)
            payload.extend(chunk)
        if b"\r\n" not in payload:
            return bytes(payload)

        _, _, application = payload.partition(b"\r\n")
        while b"\n" not in application:
            chunk = connection.recv(4096)
            if not chunk:
                break
            payload.extend(chunk)
            _, _, application = payload.partition(b"\r\n")
        return bytes(payload)


def _new_listener(address: str, port: int = 0) -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((address, port))
    listener.listen(32)
    return listener


def _backend_pair(port: int, role: str, expect_proxy: bool) -> tuple[_BackendListener, _BackendListener]:
    listener_a = _new_listener("127.0.0.2", port)
    try:
        listener_b = _new_listener("127.0.0.3", int(listener_a.getsockname()[1]))
    except BaseException:
        listener_a.close()
        raise
    return (
        _BackendListener(listener_a, f"{role}-A", expect_proxy),
        _BackendListener(listener_b, f"{role}-B", expect_proxy),
    )


def _backend_at(address: str, port: int, marker: str, expect_proxy: bool) -> _BackendListener:
    return _BackendListener(_new_listener(address, port), marker, expect_proxy)


def _free_port() -> int:
    reservation = _new_listener("127.0.0.1")
    try:
        return int(reservation.getsockname()[1])
    finally:
        reservation.close()


def _wait_until(action, description: str, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            result = action()
            if result:
                return result
        except (ConnectionError, OSError, ValueError, AssertionError) as exc:
            last_error = exc
        time.sleep(0.05)
    detail = f"; last error: {last_error}" if last_error else ""
    raise AssertionError(f"timed out waiting for {description}{detail}")


def _runtime_command(socket_path: Path, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(2)
        client.connect(str(socket_path))
        client.sendall(command.encode("ascii") + b"\n")
        client.shutdown(socket.SHUT_WR)
        chunks: list[bytes] = []
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def _server_states(socket_path: Path) -> dict[tuple[str, str], dict[str, str]]:
    output = _runtime_command(socket_path, "show servers state")
    fields: list[str] | None = None
    result: dict[tuple[str, str], dict[str, str]] = {}
    for line in output.splitlines():
        if line.startswith("#"):
            fields = line.lstrip("# ").split()
            continue
        if fields is None or not line or line == "1":
            continue
        values = line.split()
        if len(values) < len(fields):
            continue
        row = dict(zip(fields, values))
        result[(row["be_name"], row["srv_name"])] = row
    return result


def _server_addresses(socket_path: Path) -> dict[tuple[str, str], str]:
    return {server: state["srv_addr"] for server, state in _server_states(socket_path).items()}


def _backend_states(socket_path: Path, backend: str) -> list[dict[str, str]]:
    return [
        state
        for (backend_name, _), state in _server_states(socket_path).items()
        if backend_name == backend
    ]


def _address_is_up(socket_path: Path, backend: str, address: str) -> bool:
    return any(
        state["srv_addr"] == address and state["srv_op_state"] == "2"
        for state in _backend_states(socket_path, backend)
    )


def _address_is_down(socket_path: Path, backend: str, address: str) -> bool:
    return any(
        state["srv_addr"] == address and state["srv_op_state"] != "2"
        for state in _backend_states(socket_path, backend)
    )


def _address_is_unassigned(socket_path: Path, backend: str, address: str) -> bool:
    states = _backend_states(socket_path, backend)
    return bool(states) and all(state["srv_addr"] != address for state in states)


def _backend_has_no_up_server(socket_path: Path, backend: str) -> bool:
    states = _backend_states(socket_path, backend)
    return bool(states) and all(state["srv_op_state"] != "2" for state in states)


def _runtime_pid(socket_path: Path) -> int:
    output = _runtime_command(socket_path, "show info")
    for line in output.splitlines():
        if line.startswith("Pid:"):
            return int(line.partition(":")[2].strip())
    raise ValueError(f"Pid is missing from show info: {output!r}")


def _receive_line(client: socket.socket) -> bytes:
    marker = bytearray()
    while b"\n" not in marker:
        chunk = client.recv(512)
        if not chunk:
            break
        marker.extend(chunk)
    return bytes(marker)


def _connect(port: int, payload: bytes) -> tuple[socket.socket, bytes]:
    client = socket.create_connection(("127.0.0.1", port), timeout=2)
    client.settimeout(2)
    client.sendall(payload)
    return client, _receive_line(client)


def _record_with(listener: _BackendListener, payload: bytes) -> bytes | None:
    return next((record for record in listener.records() if payload in record), None)


def _frontend_is_unavailable(port: int) -> bool:
    try:
        client = socket.create_connection(("127.0.0.1", port), timeout=0.5)
        client.settimeout(0.5)
        try:
            client.sendall(b"must-not-reach-a-backend\n")
            return not client.recv(1)
        finally:
            client.close()
    except (ConnectionError, OSError):
        return True


@unittest.skipUnless(os.name == "posix" and HAPROXY, "requires HAProxy on a POSIX host")
class HAProxyDnsRotationIntegrationTests(unittest.TestCase):
    def test_dns_rotation_preserves_streams_and_proxy_protocol_semantics(self) -> None:
        chat_a = chat_b = media_a = media_b = None
        try:
            chat_a, chat_b = _backend_pair(0, "chat", True)
            media_a, media_b = _backend_pair(0, "media", False)
        except OSError as exc:
            for listener in (chat_a, chat_b, media_a, media_b):
                if listener is not None:
                    listener.close()
            self.skipTest(f"127.0.0.2/127.0.0.3 loopback listeners are unavailable: {exc}")

        dns = _FakeDnsServer("127.0.0.2")
        process: subprocess.Popen[str] | None = None
        held_chat: socket.socket | None = None
        held_media: socket.socket | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="wa-haproxy-dns-") as temporary:
                temp = Path(temporary)
                admin_socket = temp / "admin.sock"
                config_path = temp / "haproxy.cfg"
                chat_frontend = _free_port()
                media_frontend = _free_port()
                config_path.write_text(
                    self._config(
                        admin_socket,
                        dns.port,
                        chat_frontend,
                        media_frontend,
                        chat_a.port,
                        media_a.port,
                    ),
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

                def running_pid() -> int | None:
                    if process is None:
                        return None
                    if process.poll() is not None:
                        output = process.stdout.read() if process.stdout else ""
                        raise AssertionError(f"HAProxy exited with {process.returncode}: {output}")
                    if not admin_socket.exists():
                        return None
                    return _runtime_pid(admin_socket)

                pid_before = _wait_until(running_pid, "HAProxy runtime socket")
                self.assertEqual(pid_before, process.pid)
                expected_a = {
                    ("chat_backend", "chat_server"): "127.0.0.2",
                    ("media_backend", "media_server"): "127.0.0.2",
                }
                _wait_until(
                    lambda: all(
                        _server_addresses(admin_socket).get(server) == address
                        for server, address in expected_a.items()
                    ),
                    "both backend addresses to resolve to generation A",
                )
                state_a = _server_states(admin_socket)
                self.assertEqual(
                    state_a[("chat_backend", "chat_server")]["srv_fqdn"],
                    dns.CHAT_ALIAS,
                )
                self.assertEqual(
                    state_a[("media_backend", "media_server")]["srv_fqdn"],
                    dns.MEDIA_NAME,
                )

                chat_before = b"chat-before-rotation\n"
                media_before = b"media-before-rotation\n"
                held_chat, chat_marker = _connect(chat_frontend, chat_before)
                held_media, media_marker = _connect(media_frontend, media_before)
                self.assertEqual(chat_marker, b"chat-A\n")
                self.assertEqual(media_marker, b"media-A\n")
                chat_a_record = _wait_until(
                    lambda: _record_with(chat_a, chat_before),
                    "chat payload at generation A",
                )
                media_a_record = _wait_until(
                    lambda: _record_with(media_a, media_before),
                    "media payload at generation A",
                )
                self.assertTrue(chat_a_record.startswith(b"PROXY TCP4 "), chat_a_record)
                self.assertIn(b"\r\n" + chat_before, chat_a_record)
                self.assertEqual(media_a_record, media_before)
                self.assertFalse(media_a_record.startswith(b"PROXY "))

                dns.rotate("127.0.0.3")
                expected_b = {
                    ("chat_backend", "chat_server"): "127.0.0.3",
                    ("media_backend", "media_server"): "127.0.0.3",
                }
                _wait_until(
                    lambda: all(
                        _server_addresses(admin_socket).get(server) == address
                        for server, address in expected_b.items()
                    ),
                    "both backend addresses to rotate to generation B",
                )
                self.assertIsNone(process.poll())
                self.assertEqual(_runtime_pid(admin_socket), pid_before)
                self.assertEqual(process.pid, pid_before)
                state_b = _server_states(admin_socket)
                self.assertEqual(
                    state_b[("chat_backend", "chat_server")]["srv_fqdn"],
                    dns.CHAT_ALIAS,
                )
                self.assertEqual(
                    state_b[("media_backend", "media_server")]["srv_fqdn"],
                    dns.MEDIA_NAME,
                )

                chat_held = b"chat-held-stream-survived\n"
                media_held = b"media-held-stream-survived\n"
                held_chat.sendall(chat_held)
                held_media.sendall(media_held)
                self.assertEqual(_receive_line(held_chat), b"chat-A:" + chat_held)
                self.assertEqual(_receive_line(held_media), b"media-A:" + media_held)

                chat_after = b"chat-after-rotation\n"
                media_after = b"media-after-rotation\n"
                chat_new, chat_new_marker = _connect(chat_frontend, chat_after)
                media_new, media_new_marker = _connect(media_frontend, media_after)
                try:
                    self.assertEqual(chat_new_marker, b"chat-B\n")
                    self.assertEqual(media_new_marker, b"media-B\n")
                finally:
                    chat_new.close()
                    media_new.close()

                chat_b_record = _wait_until(
                    lambda: _record_with(chat_b, chat_after),
                    "chat payload at generation B",
                )
                media_b_record = _wait_until(
                    lambda: _record_with(media_b, media_after),
                    "media payload at generation B",
                )
                self.assertTrue(chat_b_record.startswith(b"PROXY TCP4 "), chat_b_record)
                self.assertIn(b"\r\n" + chat_after, chat_b_record)
                self.assertEqual(media_b_record, media_after)
                self.assertFalse(media_b_record.startswith(b"PROXY "))

                queries = dns.queries()
                self.assertTrue(any(name == dns.CHAT_ALIAS and query_type == 1 for name, query_type in queries))
                self.assertTrue(any(name == dns.MEDIA_NAME and query_type == 1 for name, query_type in queries))
        finally:
            for client in (held_chat, held_media):
                if client is not None:
                    client.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
            dns.close()
            for listener in (chat_a, chat_b, media_a, media_b):
                if listener is not None:
                    listener.close()

    def test_server_template_skips_blocked_dns_addresses_and_recovers(self) -> None:
        chat_a = chat_c = media_a = media_c = None
        listeners: list[_BackendListener] = []
        try:
            chat_a = _backend_at("127.0.0.2", 0, "chat-A", True)
            chat_c = _backend_at("127.0.0.4", chat_a.port, "chat-C", True)
            media_a = _backend_at("127.0.0.2", 0, "media-A", False)
            media_c = _backend_at("127.0.0.4", media_a.port, "media-C", False)
            listeners.extend((chat_a, chat_c, media_a, media_c))
        except OSError as exc:
            for listener in (chat_a, chat_c, media_a, media_c):
                if listener is not None:
                    listener.close()
            self.skipTest(f"test loopback listeners are unavailable: {exc}")

        chat_backend_port = chat_a.port
        media_backend_port = media_a.port
        dns = _FakeDnsServer("127.0.0.2")
        process: subprocess.Popen[str] | None = None
        held_chat: socket.socket | None = None
        held_media: socket.socket | None = None
        try:
            with tempfile.TemporaryDirectory(prefix="wa-haproxy-dns-pool-") as temporary:
                temp = Path(temporary)
                admin_socket = temp / "admin.sock"
                config_path = temp / "haproxy.cfg"
                chat_frontend = _free_port()
                media_frontend = _free_port()
                config_path.write_text(
                    self._pool_config(
                        admin_socket,
                        dns.port,
                        chat_frontend,
                        media_frontend,
                        chat_backend_port,
                        media_backend_port,
                    ),
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

                def running_pid() -> int | None:
                    if process is None:
                        return None
                    if process.poll() is not None:
                        output = process.stdout.read() if process.stdout else ""
                        raise AssertionError(f"HAProxy exited with {process.returncode}: {output}")
                    if not admin_socket.exists():
                        return None
                    return _runtime_pid(admin_socket)

                pid_before = _wait_until(running_pid, "HAProxy runtime socket")
                self.assertEqual(pid_before, process.pid)
                _wait_until(
                    lambda: (
                        _address_is_up(admin_socket, "chat_backend", "127.0.0.2")
                        and _address_is_up(admin_socket, "media_backend", "127.0.0.2")
                    ),
                    "initial address A to become healthy in both pools",
                    timeout=15,
                )
                initial_chat = next(
                    state
                    for state in _backend_states(admin_socket, "chat_backend")
                    if state["srv_addr"] == "127.0.0.2"
                )
                initial_media = next(
                    state
                    for state in _backend_states(admin_socket, "media_backend")
                    if state["srv_addr"] == "127.0.0.2"
                )
                self.assertEqual(initial_chat["srv_fqdn"], dns.CHAT_ALIAS)
                self.assertEqual(initial_media["srv_fqdn"], dns.MEDIA_NAME)
                self.assertEqual(
                    {
                        state["srv_fqdn"]
                        for state in _backend_states(admin_socket, "chat_backend")
                    },
                    {dns.CHAT_ALIAS},
                )
                self.assertEqual(
                    {
                        state["srv_fqdn"]
                        for state in _backend_states(admin_socket, "media_backend")
                    },
                    {dns.MEDIA_NAME},
                )

                chat_before = b"chat-before-blocked-answer\n"
                media_before = b"media-before-blocked-answer\n"
                held_chat, chat_marker = _connect(chat_frontend, chat_before)
                held_media, media_marker = _connect(media_frontend, media_before)
                self.assertEqual(chat_marker, b"chat-A\n")
                self.assertEqual(media_marker, b"media-A\n")
                chat_a_record = _wait_until(
                    lambda: _record_with(chat_a, chat_before),
                    "chat payload at address A",
                )
                media_a_record = _wait_until(
                    lambda: _record_with(media_a, media_before),
                    "media payload at address A",
                )
                self.assertTrue(chat_a_record.startswith(b"PROXY TCP4 "), chat_a_record)
                self.assertIn(b"\r\n" + chat_before, chat_a_record)
                self.assertEqual(media_a_record, media_before)
                self.assertFalse(media_a_record.startswith(b"PROXY "))

                # B deliberately has no listener. A must remain assigned and usable
                # while the resolver learns and health-checks the blocked address.
                dns.rotate("127.0.0.3")
                _wait_until(
                    lambda: (
                        _address_is_down(admin_socket, "chat_backend", "127.0.0.3")
                        and _address_is_down(admin_socket, "media_backend", "127.0.0.3")
                    ),
                    "blocked address B to be retained as DOWN in both pools",
                    timeout=15,
                )
                self.assertTrue(_address_is_up(admin_socket, "chat_backend", "127.0.0.2"))
                self.assertTrue(_address_is_up(admin_socket, "media_backend", "127.0.0.2"))

                chat_while_blocked = b"chat-while-b-is-blocked\n"
                media_while_blocked = b"media-while-b-is-blocked\n"
                chat_client, chat_marker = _connect(chat_frontend, chat_while_blocked)
                media_client, media_marker = _connect(media_frontend, media_while_blocked)
                try:
                    self.assertEqual(chat_marker, b"chat-A\n")
                    self.assertEqual(media_marker, b"media-A\n")
                finally:
                    chat_client.close()
                    media_client.close()
                self.assertEqual(_runtime_pid(admin_socket), pid_before)

                # C is reachable. Once learned, make A unavailable for new
                # connections; HAProxy must fail over without replacing the process.
                dns.rotate("127.0.0.4")
                _wait_until(
                    lambda: (
                        _address_is_up(admin_socket, "chat_backend", "127.0.0.4")
                        and _address_is_up(admin_socket, "media_backend", "127.0.0.4")
                    ),
                    "address C to become healthy in both pools",
                    timeout=15,
                )
                chat_a.stop_accepting()
                media_a.stop_accepting()
                _wait_until(
                    lambda: (
                        not _address_is_up(admin_socket, "chat_backend", "127.0.0.2")
                        and not _address_is_up(admin_socket, "media_backend", "127.0.0.2")
                    ),
                    "address A to stop receiving new connections",
                    timeout=10,
                )

                chat_held = b"chat-held-stream-survived-failover\n"
                media_held = b"media-held-stream-survived-failover\n"
                held_chat.sendall(chat_held)
                held_media.sendall(media_held)
                self.assertEqual(_receive_line(held_chat), b"chat-A:" + chat_held)
                self.assertEqual(_receive_line(held_media), b"media-A:" + media_held)

                chat_after = b"chat-after-failover\n"
                media_after = b"media-after-failover\n"
                chat_client, chat_marker = _connect(chat_frontend, chat_after)
                media_client, media_marker = _connect(media_frontend, media_after)
                try:
                    self.assertEqual(chat_marker, b"chat-C\n")
                    self.assertEqual(media_marker, b"media-C\n")
                finally:
                    chat_client.close()
                    media_client.close()
                chat_c_record = _wait_until(
                    lambda: _record_with(chat_c, chat_after),
                    "chat payload at address C",
                )
                media_c_record = _wait_until(
                    lambda: _record_with(media_c, media_after),
                    "media payload at address C",
                )
                self.assertTrue(chat_c_record.startswith(b"PROXY TCP4 "), chat_c_record)
                self.assertIn(b"\r\n" + chat_after, chat_c_record)
                self.assertEqual(media_c_record, media_after)
                self.assertFalse(media_c_record.startswith(b"PROXY "))
                self.assertEqual(_runtime_pid(admin_socket), pid_before)

                _wait_until(
                    lambda: all(
                        _address_is_unassigned(admin_socket, backend, address)
                        for backend in ("chat_backend", "media_backend")
                        for address in ("127.0.0.2", "127.0.0.3")
                    ),
                    "obsolete addresses A and B to expire from both pools",
                    timeout=10,
                )

                # With every discovered address unavailable, new connections fail
                # closed. Existing established streams remain independent of health.
                chat_c.stop_accepting()
                media_c.stop_accepting()
                _wait_until(
                    lambda: (
                        _backend_has_no_up_server(admin_socket, "chat_backend")
                        and _backend_has_no_up_server(admin_socket, "media_backend")
                    ),
                    "all discovered addresses to become DOWN",
                    timeout=10,
                )
                _wait_until(
                    lambda: _frontend_is_unavailable(chat_frontend),
                    "chat frontend to fail closed",
                )
                _wait_until(
                    lambda: _frontend_is_unavailable(media_frontend),
                    "media frontend to fail closed",
                )
                self.assertEqual(_runtime_pid(admin_socket), pid_before)

                chat_still_held = b"chat-held-stream-survived-all-down\n"
                media_still_held = b"media-held-stream-survived-all-down\n"
                held_chat.sendall(chat_still_held)
                held_media.sendall(media_still_held)
                self.assertEqual(
                    _receive_line(held_chat),
                    b"chat-A:" + chat_still_held,
                )
                self.assertEqual(
                    _receive_line(held_media),
                    b"media-A:" + media_still_held,
                )

                chat_recovered = _backend_at(
                    "127.0.0.4",
                    chat_backend_port,
                    "chat-C-recovered",
                    True,
                )
                media_recovered = _backend_at(
                    "127.0.0.4",
                    media_backend_port,
                    "media-C-recovered",
                    False,
                )
                listeners.extend((chat_recovered, media_recovered))
                _wait_until(
                    lambda: (
                        _address_is_up(admin_socket, "chat_backend", "127.0.0.4")
                        and _address_is_up(admin_socket, "media_backend", "127.0.0.4")
                    ),
                    "address C to recover automatically",
                    timeout=10,
                )

                chat_recovery = b"chat-after-recovery\n"
                media_recovery = b"media-after-recovery\n"
                chat_client, chat_marker = _connect(chat_frontend, chat_recovery)
                media_client, media_marker = _connect(media_frontend, media_recovery)
                try:
                    self.assertEqual(chat_marker, b"chat-C-recovered\n")
                    self.assertEqual(media_marker, b"media-C-recovered\n")
                finally:
                    chat_client.close()
                    media_client.close()
                recovered_chat_record = _wait_until(
                    lambda: _record_with(chat_recovered, chat_recovery),
                    "chat payload after automatic recovery",
                )
                recovered_media_record = _wait_until(
                    lambda: _record_with(media_recovered, media_recovery),
                    "media payload after automatic recovery",
                )
                self.assertTrue(
                    recovered_chat_record.startswith(b"PROXY TCP4 "),
                    recovered_chat_record,
                )
                self.assertIn(b"\r\n" + chat_recovery, recovered_chat_record)
                self.assertEqual(recovered_media_record, media_recovery)
                self.assertFalse(recovered_media_record.startswith(b"PROXY "))
                self.assertEqual(_runtime_pid(admin_socket), pid_before)
                self.assertIsNone(process.poll())

                queries = dns.queries()
                self.assertTrue(
                    any(
                        name == dns.CHAT_ALIAS and query_type == 1
                        for name, query_type in queries
                    )
                )
                self.assertTrue(
                    any(
                        name == dns.MEDIA_NAME and query_type == 1
                        for name, query_type in queries
                    )
                )
        finally:
            for client in (held_chat, held_media):
                if client is not None:
                    client.close()
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
            dns.close()
            for listener in listeners:
                listener.close()

    @staticmethod
    def _pool_config(
        admin_socket: Path,
        dns_port: int,
        chat_frontend: int,
        media_frontend: int,
        chat_backend: int,
        media_backend: int,
    ) -> str:
        return f"""global
    stats socket {admin_socket} mode 600 level admin
    maxconn 64

defaults
    mode tcp
    timeout connect 1s
    timeout client 15s
    timeout server 15s
    timeout check 500ms

resolvers test_dns
    nameserver local 127.0.0.1:{dns_port}
    resolve_retries 2
    timeout resolve 200ms
    timeout retry 100ms
    hold valid 200ms
    hold obsolete 3s
    hold other 1s
    hold refused 1s
    hold nx 1s
    hold timeout 1s
    accepted_payload_size 4096

frontend chat_frontend
    bind 127.0.0.1:{chat_frontend}
    default_backend chat_backend

backend chat_backend
    balance leastconn
    default-server check inter 200ms fastinter 100ms downinter 100ms rise 1 fall 1 observe layer4
    server-template chat_server 4 { _FakeDnsServer.CHAT_ALIAS }:{chat_backend} send-proxy resolvers test_dns resolve-prefer ipv4 resolve-opts prevent-dup-ip init-addr last,none

frontend media_frontend
    bind 127.0.0.1:{media_frontend}
    default_backend media_backend

backend media_backend
    balance leastconn
    default-server check inter 200ms fastinter 100ms downinter 100ms rise 1 fall 1 observe layer4
    server-template media_server 4 { _FakeDnsServer.MEDIA_NAME }:{media_backend} resolvers test_dns resolve-prefer ipv4 resolve-opts prevent-dup-ip init-addr last,none
"""

    @staticmethod
    def _config(
        admin_socket: Path,
        dns_port: int,
        chat_frontend: int,
        media_frontend: int,
        chat_backend: int,
        media_backend: int,
    ) -> str:
        return f"""global
    stats socket {admin_socket} mode 600 level admin
    maxconn 64

defaults
    mode tcp
    timeout connect 1s
    timeout client 15s
    timeout server 15s
    timeout check 500ms

resolvers test_dns
    nameserver local 127.0.0.1:{dns_port}
    resolve_retries 2
    timeout resolve 200ms
    timeout retry 100ms
    hold other 1s
    hold refused 1s
    hold nx 1s
    hold timeout 1s
    accepted_payload_size 4096

frontend chat_frontend
    bind 127.0.0.1:{chat_frontend}
    default_backend chat_backend

backend chat_backend
    default-server check inter 200ms fastinter 100ms downinter 100ms rise 1 fall 1 observe layer4
    server chat_server { _FakeDnsServer.CHAT_ALIAS }:{chat_backend} send-proxy resolvers test_dns resolve-prefer ipv4 init-addr last,none

frontend media_frontend
    bind 127.0.0.1:{media_frontend}
    default_backend media_backend

backend media_backend
    default-server check inter 200ms fastinter 100ms downinter 100ms rise 1 fall 1 observe layer4
    server media_server { _FakeDnsServer.MEDIA_NAME }:{media_backend} resolvers test_dns resolve-prefer ipv4 init-addr last,none
"""


if __name__ == "__main__":
    unittest.main()
