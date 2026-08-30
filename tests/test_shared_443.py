from __future__ import annotations

import contextlib
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path


HAPROXY = shutil.which("haproxy")
OPENSSL = shutil.which("openssl")


def _integration_availability() -> tuple[bool, str]:
    if os.name != "posix":
        return False, "requires a POSIX host"
    if HAPROXY is None:
        return False, "requires HAProxy 2.8 or newer"
    try:
        result = subprocess.run(
            [HAPROXY, "-v"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"cannot query HAProxy version: {exc}"
    version_text = result.stdout + result.stderr
    match = re.search(r"\bHAProxy version (\d+)\.(\d+)", version_text)
    if result.returncode != 0 or match is None:
        return False, "cannot determine HAProxy version"
    version = (int(match.group(1)), int(match.group(2)))
    if version < (2, 8):
        return False, f"requires HAProxy 2.8 or newer, found {version[0]}.{version[1]}"
    if OPENSSL is None:
        return False, "requires OpenSSL to generate an ephemeral test certificate"
    return True, ""


INTEGRATION_AVAILABLE, INTEGRATION_SKIP_REASON = _integration_availability()


def _listener() -> socket.socket:
    result = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    result.bind(("127.0.0.1", 0))
    result.listen(32)
    result.settimeout(0.1)
    return result


def _free_ports(count: int) -> tuple[int, ...]:
    reservations = [_listener() for _ in range(count)]
    try:
        return tuple(int(item.getsockname()[1]) for item in reservations)
    finally:
        for reservation in reservations:
            reservation.close()


def _receive_until(connection: socket.socket, marker: bytes, limit: int = 65536) -> bytes:
    result = bytearray()
    while marker not in result:
        chunk = connection.recv(min(4096, limit - len(result)))
        if not chunk:
            break
        result.extend(chunk)
        if len(result) >= limit:
            raise ValueError("test backend input exceeded its limit")
    return bytes(result)


def _wait_until(action, description: str, timeout: float = 8.0):
    deadline = time.monotonic() + timeout
    last_error: BaseException | None = None
    while time.monotonic() < deadline:
        try:
            result = action()
            if result:
                return result
        except (ConnectionError, OSError, AssertionError, ValueError) as exc:
            last_error = exc
        time.sleep(0.05)
    detail = f"; last error: {last_error}" if last_error else ""
    raise AssertionError(f"timed out waiting for {description}{detail}")


class _ChatBackend:
    def __init__(self) -> None:
        self._listener = _listener()
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._records: list[bytes] = []
        self._thread = threading.Thread(target=self._accept, name="shared-443-chat", daemon=True)
        self._thread.start()

    def record_for(self, payload: bytes) -> bytes | None:
        with self._lock:
            return next((record for record in self._records if payload in record), None)

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
            threading.Thread(
                target=self._handle,
                args=(connection,),
                name="shared-443-chat-connection",
                daemon=True,
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(3)
            received = bytearray(_receive_until(connection, b"\r\n"))
            _header, separator, application = bytes(received).partition(b"\r\n")
            if not separator:
                return
            while b"\n" not in application:
                chunk = connection.recv(4096)
                if not chunk:
                    return
                received.extend(chunk)
                _header, _separator, application = bytes(received).partition(b"\r\n")
            record = bytes(received)
            with self._lock:
                self._records.append(record)
            connection.sendall(b"chat:" + application)
        except (ConnectionError, OSError, ValueError):
            pass
        finally:
            with self._lock:
                self._connections.discard(connection)
            connection.close()


class _MediaTlsBackend:
    def __init__(self, certificate: Path) -> None:
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(str(certificate))
        self._listener = _listener()
        self.port = int(self._listener.getsockname()[1])
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._connections: set[socket.socket] = set()
        self._records: list[tuple[bytes, bytes]] = []
        self._thread = threading.Thread(target=self._accept, name="shared-443-media", daemon=True)
        self._thread.start()

    def record_for(self, payload: bytes) -> tuple[bytes, bytes] | None:
        with self._lock:
            return next((record for record in self._records if record[1] == payload), None)

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
            threading.Thread(
                target=self._handle,
                args=(connection,),
                name="shared-443-media-connection",
                daemon=True,
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        active: socket.socket = connection
        try:
            connection.settimeout(3)
            initial = connection.recv(65536, socket.MSG_PEEK)
            if not initial:
                return
            tls = self._context.wrap_socket(
                connection,
                server_side=True,
                do_handshake_on_connect=False,
            )
            active = tls
            with self._lock:
                self._connections.discard(connection)
                self._connections.add(tls)
            tls.settimeout(3)
            tls.do_handshake()
            payload = _receive_until(tls, b"\n")
            if not payload:
                return
            with self._lock:
                self._records.append((initial, payload))
            tls.sendall(b"media:" + payload)
        except (ConnectionError, OSError, ValueError, ssl.SSLError):
            pass
        finally:
            with self._lock:
                self._connections.discard(connection)
                self._connections.discard(active)
            with contextlib.suppress(OSError):
                active.close()
            if active is not connection:
                with contextlib.suppress(OSError):
                    connection.close()


def _generate_certificate(directory: Path) -> Path:
    assert OPENSSL is not None
    certificate = directory / "certificate.crt"
    private_key = directory / "certificate.key"
    combined = directory / "certificate.pem"
    result = subprocess.run(
        [
            OPENSSL,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-sha256",
            "-nodes",
            "-keyout",
            str(private_key),
            "-out",
            str(certificate),
            "-days",
            "1",
            "-subj",
            "/CN=proxy.test",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=15,
    )
    if result.returncode != 0:
        raise AssertionError(f"OpenSSL certificate generation failed: {result.stderr}")
    combined.write_bytes(certificate.read_bytes() + b"\n" + private_key.read_bytes())
    combined.chmod(0o600)
    return combined


def _flush_tls_output(
    wire: socket.socket,
    outgoing: ssl.MemoryBIO,
    *,
    fragment_first_flight: bool,
    first_flight_fragmented: bool,
) -> bool:
    encrypted = outgoing.read()
    if not encrypted:
        return first_flight_fragmented
    if fragment_first_flight and not first_flight_fragmented:
        if len(encrypted) < 8:
            raise AssertionError("TLS ClientHello was too short to fragment")
        split = 7
        wire.sendall(encrypted[:split])
        time.sleep(0.15)
        wire.sendall(encrypted[split:])
        return True
    wire.sendall(encrypted)
    return first_flight_fragmented


def _tls_exchange(
    port: int,
    sni: str | None,
    payload: bytes,
    expected_response: bytes,
    *,
    fragment_client_hello: bool = False,
) -> tuple[bytes, bool]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    incoming = ssl.MemoryBIO()
    outgoing = ssl.MemoryBIO()
    tls = context.wrap_bio(
        incoming,
        outgoing,
        server_side=False,
        server_hostname=sni,
    )
    fragmented = False

    with socket.create_connection(("127.0.0.1", port), timeout=3) as wire:
        wire.settimeout(3)
        wire.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            try:
                tls.do_handshake()
                fragmented = _flush_tls_output(
                    wire,
                    outgoing,
                    fragment_first_flight=fragment_client_hello,
                    first_flight_fragmented=fragmented,
                )
                break
            except ssl.SSLWantReadError:
                fragmented = _flush_tls_output(
                    wire,
                    outgoing,
                    fragment_first_flight=fragment_client_hello,
                    first_flight_fragmented=fragmented,
                )
                encrypted = wire.recv(65536)
                if not encrypted:
                    raise ConnectionError("TLS peer closed during handshake")
                incoming.write(encrypted)
            except ssl.SSLWantWriteError:
                fragmented = _flush_tls_output(
                    wire,
                    outgoing,
                    fragment_first_flight=fragment_client_hello,
                    first_flight_fragmented=fragmented,
                )

        offset = 0
        while offset < len(payload):
            try:
                offset += tls.write(payload[offset:])
            except ssl.SSLWantReadError:
                encrypted = wire.recv(65536)
                if not encrypted:
                    raise ConnectionError("TLS peer closed while sending application data")
                incoming.write(encrypted)
            fragmented = _flush_tls_output(
                wire,
                outgoing,
                fragment_first_flight=False,
                first_flight_fragmented=fragmented,
            )

        response = bytearray()
        while len(response) < len(expected_response):
            try:
                chunk = tls.read(len(expected_response) - len(response))
                if not chunk:
                    break
                response.extend(chunk)
            except ssl.SSLWantReadError:
                fragmented = _flush_tls_output(
                    wire,
                    outgoing,
                    fragment_first_flight=False,
                    first_flight_fragmented=fragmented,
                )
                encrypted = wire.recv(65536)
                if not encrypted:
                    raise ConnectionError("TLS peer closed before the expected response")
                incoming.write(encrypted)
            except ssl.SSLWantWriteError:
                fragmented = _flush_tls_output(
                    wire,
                    outgoing,
                    fragment_first_flight=False,
                    first_flight_fragmented=fragmented,
                )
        return bytes(response), fragmented


class _Shared443Harness:
    def __init__(self) -> None:
        assert HAPROXY is not None
        self._temporary = tempfile.TemporaryDirectory(prefix="wa-haproxy-shared-443-")
        self._process: subprocess.Popen[str] | None = None
        self.chat: _ChatBackend | None = None
        self.media: _MediaTlsBackend | None = None
        try:
            directory = Path(self._temporary.name)
            certificate = _generate_certificate(directory)
            self.chat = _ChatBackend()
            self.media = _MediaTlsBackend(certificate)
            self.shared_port, self.chat_loopback_port, self.media_fallback_port = _free_ports(3)
            admin_socket = directory / "admin.sock"
            config = directory / "haproxy.cfg"
            config.write_text(
                self._config(admin_socket, certificate),
                encoding="utf-8",
                newline="\n",
            )
            validation = subprocess.run(
                [HAPROXY, "-c", "-f", str(config)],
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )
            if validation.returncode != 0:
                raise AssertionError(validation.stdout + validation.stderr)
            self._process = subprocess.Popen(
                [HAPROXY, "-db", "-f", str(config)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )

            def process_ready() -> bool:
                assert self._process is not None
                if self._process.poll() is not None:
                    output = self._process.stdout.read() if self._process.stdout else ""
                    raise AssertionError(
                        f"HAProxy exited with {self._process.returncode}: {output}"
                    )
                return admin_socket.exists()

            _wait_until(process_ready, "HAProxy shared-443 runtime socket")
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> _Shared443Harness:
        return self

    def __exit__(self, _exc_type, _exc, _traceback) -> None:
        self.close()

    def close(self) -> None:
        if self._process is not None:
            if self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self._process.kill()
                    self._process.wait(timeout=5)
            if self._process.stdout is not None:
                self._process.stdout.close()
            self._process = None
        if self.media is not None:
            self.media.close()
            self.media = None
        if self.chat is not None:
            self.chat.close()
            self.chat = None
        self._temporary.cleanup()

    def _config(self, admin_socket: Path, certificate: Path) -> str:
        assert self.chat is not None
        assert self.media is not None
        return f"""global
    stats socket {admin_socket} mode 600 level admin
    maxconn 64
    tune.bufsize 16384

defaults
    mode tcp
    timeout connect 2s
    timeout client 8s
    timeout server 8s

frontend whatsapp_shared_443
    bind 127.0.0.1:{self.shared_port}
    tcp-request inspect-delay 3s
    acl shared_443_hello req.ssl_hello_type 1
    acl shared_443_media_exact req.ssl_sni,lower -m str mmg.whatsapp.net
    acl shared_443_media_suffix req.ssl_sni,lower -m end .cdn.whatsapp.net
    tcp-request content accept if shared_443_hello
    tcp-request content reject if WAIT_END
    use_backend whatsapp_media if shared_443_hello shared_443_media_exact
    use_backend whatsapp_media if shared_443_hello shared_443_media_suffix
    default_backend whatsapp_chat_tls_loop

backend whatsapp_chat_tls_loop
    server chat_tls 127.0.0.1:{self.chat_loopback_port} send-proxy

frontend whatsapp_chat_tls
    bind 127.0.0.1:{self.chat_loopback_port} accept-proxy ssl crt {certificate}
    default_backend whatsapp_chat

backend whatsapp_chat
    server chat 127.0.0.1:{self.chat.port} send-proxy

frontend whatsapp_media_fallback
    bind 127.0.0.1:{self.media_fallback_port}
    default_backend whatsapp_media

backend whatsapp_media
    server media 127.0.0.1:{self.media.port}
"""


@unittest.skipUnless(INTEGRATION_AVAILABLE, INTEGRATION_SKIP_REASON)
class HAProxyShared443IntegrationTests(unittest.TestCase):
    def assert_raw_media_record(
        self,
        harness: _Shared443Harness,
        payload: bytes,
    ) -> None:
        assert harness.media is not None
        initial, application = _wait_until(
            lambda: harness.media.record_for(payload),
            f"raw media payload {payload!r}",
        )
        self.assertEqual(application, payload)
        self.assertEqual(initial[:1], b"\x16", initial)
        self.assertFalse(initial.startswith(b"PROXY "), initial)

    def assert_single_proxy_chat_record(
        self,
        harness: _Shared443Harness,
        payload: bytes,
    ) -> None:
        assert harness.chat is not None
        record = _wait_until(
            lambda: harness.chat.record_for(payload),
            f"chat payload {payload!r}",
        )
        header, separator, application = record.partition(b"\r\n")
        self.assertEqual(separator, b"\r\n", record)
        self.assertTrue(header.startswith(b"PROXY TCP4 "), record)
        self.assertEqual(record.count(b"PROXY "), 1, record)
        self.assertEqual(application, payload)

    def test_exact_and_suffix_media_sni_are_raw_without_proxy_protocol(self) -> None:
        with _Shared443Harness() as harness:
            cases = (
                ("MMG.WHATSAPP.NET", b"media-exact\n"),
                ("MEDIA-HEL3-1.CDN.WHATSAPP.NET", b"media-suffix\n"),
            )
            for sni, payload in cases:
                with self.subTest(sni=sni):
                    expected = b"media:" + payload
                    response, fragmented = _tls_exchange(
                        harness.shared_port,
                        sni,
                        payload,
                        expected,
                    )
                    self.assertEqual(response, expected)
                    self.assertFalse(fragmented)
                    self.assert_raw_media_record(harness, payload)

    def test_unknown_and_absent_sni_take_chat_tls_loop_with_one_proxy_v1(self) -> None:
        with _Shared443Harness() as harness:
            cases = (
                ("unknown.example", b"chat-unknown-sni\n"),
                (None, b"chat-no-sni\n"),
            )
            for sni, payload in cases:
                with self.subTest(sni=sni):
                    expected = b"chat:" + payload
                    response, fragmented = _tls_exchange(
                        harness.shared_port,
                        sni,
                        payload,
                        expected,
                    )
                    self.assertEqual(response, expected)
                    self.assertFalse(fragmented)
                    self.assert_single_proxy_chat_record(harness, payload)

    def test_fragmented_client_hello_is_still_routed_by_media_suffix(self) -> None:
        with _Shared443Harness() as harness:
            payload = b"media-fragmented-client-hello\n"
            expected = b"media:" + payload
            response, fragmented = _tls_exchange(
                harness.shared_port,
                "fragmented.cdn.whatsapp.net",
                payload,
                expected,
                fragment_client_hello=True,
            )
            self.assertTrue(fragmented)
            self.assertEqual(response, expected)
            self.assert_raw_media_record(harness, payload)

    def test_non_tls_payload_is_rejected_without_entering_chat_loop(self) -> None:
        with _Shared443Harness() as harness:
            payload = b"not-a-tls-client-hello\n"
            started = time.monotonic()
            with socket.create_connection(
                ("127.0.0.1", harness.shared_port),
                timeout=3,
            ) as connection:
                connection.settimeout(5)
                connection.sendall(payload)
                self.assertEqual(connection.recv(1), b"")
            self.assertLess(time.monotonic() - started, 4.5)
            assert harness.chat is not None
            self.assertIsNone(harness.chat.record_for(payload))

    def test_media_fallback_listener_remains_raw_without_proxy_protocol(self) -> None:
        with _Shared443Harness() as harness:
            payload = b"media-fallback-listener\n"
            expected = b"media:" + payload
            response, fragmented = _tls_exchange(
                harness.media_fallback_port,
                "fallback.example",
                payload,
                expected,
            )
            self.assertEqual(response, expected)
            self.assertFalse(fragmented)
            self.assert_raw_media_record(harness, payload)


if __name__ == "__main__":
    unittest.main()
