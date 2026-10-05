"""One-use loopback form: no request logging, URL keys, browser storage or external assets."""

from __future__ import annotations

import hmac
import html
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs

from polaris.onboarding.errors import OnboardingProblem

Accept = Callable[[str], dict[str, Any]]


def open_browser(url: str) -> None:
    # Do not honor BROWSER or a project-selected executable.
    if sys.platform == "darwin":
        try:
            subprocess.run(
                ["/usr/bin/open", url], check=False, timeout=5,
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": os.defpath, "HOME": os.path.expanduser("~")},
            )
        except (OSError, subprocess.TimeoutExpired):
            pass


class PrivateForm(HTTPServer):
    allow_reuse_address = False

    def __init__(self, api_url: str, accept: Accept, timeout: float) -> None:
        self.api_url = api_url
        self.accept = accept
        self.deadline = time.monotonic() + timeout
        self.session = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(32)
        self.result: dict[str, Any] | None = None
        super().__init__(("127.0.0.1", 0), FormHandler)
        self.origin = f"http://127.0.0.1:{self.server_port}"
        self.url = f"{self.origin}/{self.session}"
        self.timeout = 0.2

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(2)
        return connection, address

    def handle_error(self, request: Any, client_address: Any) -> None:
        # HTTP tracebacks can contain body data; no handler exception is logged.
        pass


class FormHandler(BaseHTTPRequestHandler):
    server: PrivateForm
    server_version = "Theo"
    sys_version = ""
    protocol_version = "HTTP/1.0"

    def setup(self) -> None:
        super().setup()
        self._request_timer = threading.Timer(
            max(0.01, min(10.0, self.server.deadline - time.monotonic())), self._expire_request,
        )
        self._request_timer.daemon = True
        self._request_timer.start()

    def _expire_request(self) -> None:
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self) -> None:
        self._request_timer.cancel()
        super().finish()

    def log_message(self, format: str, *args: Any) -> None:
        pass

    def _valid_request(self, *, post: bool = False) -> bool:
        if (time.monotonic() >= self.server.deadline or self.server.result is not None
                or self.headers.get_all("Host") != [self.server.origin.removeprefix("http://")]
                or not self.path.isascii() or not hmac.compare_digest(self.path, "/" + self.server.session)):
            return False
        origins = self.headers.get_all("Origin")
        if post and origins != [self.server.origin]:
            return False
        if origins is not None and origins != [self.server.origin]:
            return False
        return self.headers.get("Sec-Fetch-Site") in (None, "none", "same-origin")

    def _reply(self, status: int, message: str, *, form: bool = False) -> None:
        inputs = (
            f'<form method="post" action="/{self.server.session}" autocomplete="off">'
            f'<input type="hidden" name="csrf" value="{self.server.csrf}">'
            '<label for="key">Polaris API key</label>'
            '<input id="key" name="key" type="password" required minlength="8" maxlength="2048" '
            'autocomplete="off" autocapitalize="none" spellcheck="false" autofocus>'
            '<button type="submit">Activate Polaris</button></form>'
        ) if form else ""
        body = (
            '<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            '<title>Theo · Private activation</title><style>'
            'body{font:17px system-ui;background:#0d1420;color:#edf5ff;max-width:32rem;'
            'margin:10vh auto;padding:2rem}h1{font-size:3rem;letter-spacing:.22em;color:#8be0ee}'
            'p{line-height:1.6}input,button{box-sizing:border-box;display:block;width:100%;'
            'margin:1rem 0;padding:.85rem;border-radius:.55rem;font:inherit}'
            'button{background:#8be0ee;color:#0d1420;cursor:pointer}small{color:#b8c4d4}'
            '</style><h1>THEO</h1><h2>Private Polaris activation</h2>'
            f'<p>{html.escape(message)}</p>{inputs}'
            f'<p><small>Endpoint: {html.escape(self.server.api_url)}<br>'
            'This short-lived form runs only on your computer. The key is sent only to that '
            'endpoint for validation and stored privately on this computer, never in the project '
            'or browser storage.</small></p></html>'
        ).encode()
        self.send_response(status)
        for name, value in (
            ("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store, max-age=0"), ("Pragma", "no-cache"),
            ("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "
             "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"),
            ("Connection", "close"),
        ):
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_GET(self) -> None:
        if not self._valid_request():
            self._reply(404, "This activation session is unavailable or expired.")
            return
        self._reply(200, "Enter your Polaris-issued key here, not in your coding agent's chat.", form=True)

    def do_POST(self) -> None:
        if not self._valid_request(post=True):
            self._reply(403, "This activation request was not accepted.")
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or not lengths[0].isdigit() or not 1 <= int(lengths[0]) <= 4096
                or self.headers.get("Transfer-Encoding") is not None
                or self.headers.get_all("Content-Type") != ["application/x-www-form-urlencoded"]):
            self._reply(400, "Use the private key form in this window.")
            return
        try:
            body = self.rfile.read(int(lengths[0]))
            if len(body) != int(lengths[0]):
                raise ValueError
            values = parse_qs(body.decode("utf-8"), strict_parsing=True, max_num_fields=2)
            if (set(values) != {"csrf", "key"} or any(len(value) != 1 for value in values.values())
                    or not values["csrf"][0].isascii()
                    or not hmac.compare_digest(values["csrf"][0], self.server.csrf)):
                raise ValueError
        except (ValueError, UnicodeError, TimeoutError):
            self._reply(400, "Use the private key form in this window.")
            return
        if time.monotonic() >= self.server.deadline:
            self._reply(403, "This activation session expired. Rerun Theo to open a new one.")
            return
        self._request_timer.cancel()
        try:
            result = self.server.accept(values["key"][0].strip())
        except OnboardingProblem as exc:
            self._reply(400, exc.message, form=True)
            return
        except Exception:
            self._reply(400, "Activation could not finish. No success is being reported; retry from the terminal.")
            return
        self.server.result = result
        self._reply(200, "Polaris authentication and model availability are verified. You can close this window and return to your coding agent.")


def browser_activation(api_url: str, accept: Accept, *, timeout: float = 180,
                       notify: Callable[[str], None] | None = None) -> dict[str, Any]:
    if not 1 <= timeout <= 600:
        raise OnboardingProblem("invalid_timeout", "Private browser activation timeout must be between 1 and 600 seconds.")
    with PrivateForm(api_url, accept, timeout) as server:
        if notify is not None:
            notify(server.url)
        open_browser(server.url)
        while server.result is None and time.monotonic() < server.deadline:
            server.handle_request()
        if server.result is None:
            raise OnboardingProblem("activation_expired", "Private key entry expired. Rerun the same setup command to resume; installed files are retained.", exit_code=1)
        return server.result
