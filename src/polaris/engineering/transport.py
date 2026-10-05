"""Small explicit HTTP transport: no proxies, redirects, retries, cookies, logging, or tools."""

from __future__ import annotations

import http.client
import queue
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from pydantic import SecretStr

from polaris.engineering.actions import scope_url
from polaris.engineering.generation_models import GenerationCode


class TransportError(Exception):
    def __init__(self, code: GenerationCode) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class HTTPResult:
    status: int
    body: bytes = field(repr=False)


class GenerationTransport(Protocol):
    def __call__(
        self, endpoint: str, *, body: bytes, api_key: SecretStr | None,
        timeout_seconds: float, max_response_bytes: int,
    ) -> HTTPResult: ...


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TransportError("timeout")
    return remaining


def _resolve(host: str, port: int, deadline: float) -> list[Any]:
    # OS DNS can ignore socket timeouts. A timed-out daemon may finish DNS later, but
    # cannot open sockets, send source, or access credentials.
    results: queue.Queue[list[Any] | None] = queue.Queue(maxsize=1)

    def lookup() -> None:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            results.put(addresses[:32])
        except OSError:
            results.put(None)

    threading.Thread(target=lookup, name="polaris-generation-dns", daemon=True).start()
    try:
        resolved = results.get(timeout=_remaining(deadline))
    except queue.Empty:
        raise TransportError("timeout") from None
    if not resolved:
        raise TransportError("provider_error")
    return resolved


class _Connection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, *, secure: bool, deadline: float) -> None:
        super().__init__(host, port, timeout=_remaining(deadline))
        self.secure = secure
        self.deadline = deadline

    def connect(self) -> None:
        addresses = _resolve(self.host, self.port, self.deadline)
        connected: socket.socket | None = None
        for family, socktype, protocol, _, address in addresses:
            candidate = socket.socket(family, socktype, protocol)
            self.sock = candidate
            try:
                candidate.settimeout(_remaining(self.deadline))
                candidate.connect(address)
                connected = candidate
                break
            except OSError:
                candidate.close()
                self.sock = None
        if connected is None:
            raise TransportError("provider_error")
        connected.settimeout(_remaining(self.deadline))
        if self.secure:
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(connected, server_hostname=self.host)
        _remaining(self.deadline)

    def abort(self) -> None:
        active = self.sock
        if active is not None:
            try:
                active.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        self.close()


def http_transport(
    endpoint: str, *, body: bytes, api_key: SecretStr | None,
    timeout_seconds: float, max_response_bytes: int,
) -> HTTPResult:
    """One bounded request to an already validated application-configured endpoint."""
    scheme, host, port, path = scope_url(endpoint)
    deadline = time.monotonic() + timeout_seconds
    connection = _Connection(host, port, secure=scheme == "https", deadline=deadline)
    watchdog = threading.Timer(timeout_seconds, connection.abort)
    watchdog.daemon = True
    watchdog.start()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key is not None:
        headers["Authorization"] = "Bearer " + api_key.get_secret_value()
    try:
        connection.connect()
        _remaining(deadline)
        if connection.sock is not None:
            connection.sock.settimeout(_remaining(deadline))
        connection.request("POST", path, body=body, headers=headers)
        response = connection.getresponse()
        # Never follow Location, including same-host redirects. Error bodies are not read.
        if response.status != 200:
            return HTTPResult(status=response.status, body=b"")
        content_length = response.getheader("Content-Length")
        if content_length is not None:
            try:
                length = int(content_length)
            except ValueError:
                raise TransportError("invalid_response") from None
            if not 0 <= length <= max_response_bytes:
                raise TransportError("output_limit")
        if response.getheader("Content-Encoding", "identity").lower() != "identity":
            raise TransportError("invalid_response")
        chunks: list[bytes] = []
        size = 0
        while True:
            _remaining(deadline)
            if connection.sock is not None:
                connection.sock.settimeout(_remaining(deadline))
            chunk = response.read1(min(65_536, max_response_bytes + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > max_response_bytes:
                raise TransportError("output_limit")
        _remaining(deadline)
        return HTTPResult(status=response.status, body=b"".join(chunks))
    except TransportError:
        raise
    except (OSError, http.client.HTTPException, ValueError):
        code: GenerationCode = "timeout" if time.monotonic() >= deadline else "provider_error"
        raise TransportError(code) from None
    finally:
        watchdog.cancel()
        connection.abort()
        headers.clear()
