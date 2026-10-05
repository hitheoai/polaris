"""Private activation security, using synthetic keys and loopback-only test servers."""

from __future__ import annotations

import http.client
import io
import json
import re
import threading
import time
import urllib.parse
from types import SimpleNamespace

import pytest

from polaris.client import PolarisAPIError
from polaris.onboarding import auth, browser
from polaris.onboarding.errors import OnboardingProblem
from polaris.remote import (
    connect,
    credentials_path,
    load_credentials,
    normalize_api_url,
    save_credentials,
)

KEY = "plk_synthetic_private_fixture"


class FakeClient:
    loaded = True
    failure = None

    def __init__(self, url, *, api_key, timeout):
        self.api_key = api_key

    def usage(self):
        if self.failure:
            raise self.failure
        return SimpleNamespace(key_id="fixture-id")

    def models(self):
        return SimpleNamespace(model=SimpleNamespace(
            loaded=self.loaded, identity=object() if self.loaded else None,
            supported_checks=["sql_injection", "command_injection"],
        ))


@pytest.fixture
def fake_api(monkeypatch):
    monkeypatch.setattr("polaris.client.PolarisClient", FakeClient)
    monkeypatch.setattr(FakeClient, "loaded", True)
    monkeypatch.setattr(FakeClient, "failure", None)
    return FakeClient


@pytest.mark.parametrize("url", [
    "", "http://api.example", "https://name:password@api.example", "https://api.example/path",
    "https://api.example?key=synthetic", "https://api.example/#key", "https://api.example\\path",
    " https://api.example", "https://api.example\n", "https://api.example:99999",
])
def test_unsafe_activation_origins_are_rejected_without_echo(url):
    with pytest.raises(OnboardingProblem) as error:
        auth.endpoint(url)
    assert "password" not in error.value.message and "synthetic" not in error.value.message


def test_explicit_loopback_api_is_supported_for_operator_validation():
    assert auth.endpoint("http://127.0.0.1:8123/") == "http://127.0.0.1:8123"
    assert auth.endpoint("http://[::1]:8123") == "http://[::1]:8123"


@pytest.mark.parametrize(("before", "after"), [
    ("HTTPS://API.EXAMPLE:443/", "https://api.example"),
    ("http://127.0.0.1:80/", "http://127.0.0.1"),
    ("https://[0:0:0:0:0:0:0:1]:443/", "https://[::1]"),
    ("https://Api.Example:444/", "https://api.example:444"),
])
def test_canonical_origin_contract(before, after):
    assert normalize_api_url(before) == after


@pytest.mark.parametrize("url", [
    "https://api.example?", "https://api.example#", "https://api.example:",
    "https://api.example:abc", "https://api.example:0", "https://a..example",
    "https://[::1]garbage", "https://[::1]:", "https://-bad.example",
    "http://localhost", "https://api.example/" + "a" * 2048,
])
def test_normalizer_rejects_ambiguous_authorities(url):
    with pytest.raises(ValueError):
        normalize_api_url(url)


def test_unready_model_is_not_saved(fake_api, monkeypatch):
    monkeypatch.setattr(FakeClient, "loaded", False)
    with pytest.raises(OnboardingProblem, match="model is not ready"):
        auth.check_key("https://api.example", KEY)
    assert load_credentials() is None


def test_remote_error_body_cannot_leak_a_key(fake_api, monkeypatch):
    monkeypatch.setattr(FakeClient, "failure", PolarisAPIError(500, KEY, f"Reflected: {KEY}"))
    with pytest.raises(OnboardingProblem) as error:
        auth.check_key("https://api.example", KEY)
    assert KEY not in str(error.value)


def test_saved_matching_activation_is_revalidated_and_private(fake_api):
    path = save_credentials("https://api.example", KEY)
    value = auth.activate("https://api.example")
    assert value["auth_verified"] and value["model_ready"]
    assert path.stat().st_mode & 0o777 == 0o600
    assert KEY not in json.dumps(value)


def test_unrelated_key_is_not_sent_to_a_new_origin(fake_api, monkeypatch):
    save_credentials("https://other.example", KEY)
    monkeypatch.setattr("sys.stdin", io.StringIO())
    seen = []

    def handoff(url, accept, **kwargs):
        seen.append(url)
        return {"status": "private_input_pending"}

    monkeypatch.setattr(browser, "browser_activation", handoff)
    assert auth.activate("https://approved.example")["status"] == "private_input_pending"
    assert seen == ["https://approved.example"] and load_credentials().api_url == "https://other.example"


def test_file_only_mode_ignores_environment_and_enforces_endpoint_pin(monkeypatch):
    save_credentials("https://approved.example", KEY)
    monkeypatch.setenv("POLARIS_API_KEY", "plk_unrelated_ambient_fixture")
    monkeypatch.setenv("POLARIS_API_URL", "https://other.example")
    monkeypatch.setenv("POLARIS_CREDENTIAL_SOURCE", "file")
    monkeypatch.setenv("POLARIS_EXPECTED_API_URL", "https://approved.example")
    assert load_credentials().api_url == "https://approved.example"
    assert load_credentials().api_key == KEY
    monkeypatch.setenv("POLARIS_EXPECTED_API_URL", "https://other.example")
    assert load_credentials() is None
    with pytest.raises(Exception, match="approved API origin"):
        connect()


def test_world_readable_or_symlinked_credentials_are_not_consumed(tmp_path):
    path = save_credentials("https://api.example", KEY)
    path.chmod(0o644)
    assert load_credentials() is None
    path.unlink()
    target = tmp_path / "fixture-secret"
    target.write_text("unrelated")
    path.symlink_to(target)
    with pytest.raises(OSError, match="symbolic link"):
        save_credentials("https://api.example", KEY)
    assert target.read_text() == "unrelated"


def test_symlinked_credential_parent_cannot_redirect_writes(tmp_path, monkeypatch):
    destination = tmp_path / "target"
    destination.mkdir()
    link = tmp_path / "link"
    link.symlink_to(destination, target_is_directory=True)
    monkeypatch.setattr("polaris.remote.credentials_path", lambda: link / "credentials.json")
    with pytest.raises(OSError, match="symbolic link"):
        save_credentials("https://api.example", KEY)
    assert list(destination.iterdir()) == []


def test_private_terminal_input_is_required_without_browser(monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO())
    with pytest.raises(OnboardingProblem, match="No private terminal"):
        auth.activate("https://api.example", method="terminal")


@pytest.fixture
def form():
    accepted = []

    def accept(key):
        accepted.append(key)
        return {"status": "verified", "auth_verified": True}

    with browser.PrivateForm("https://api.example", accept, 30) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server, accepted
        server.shutdown()
        thread.join(timeout=5)


def request(server, method="GET", *, path=None, body=None, origin=None, host=None, extra=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    headers = {"Host": host or f"127.0.0.1:{server.server_port}"}
    if origin:
        headers["Origin"] = origin
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    headers.update(extra or {})
    connection.request(method, path or "/" + server.session, body=body, headers=headers)
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read().decode()
    connection.close()
    return result


def test_browser_form_has_no_external_assets_storage_or_key_urls(form, capsys):
    server, accepted = form
    status, headers, body = request(server)
    assert status == 200 and 'type="password"' in body
    assert headers["Cache-Control"].startswith("no-store")
    assert headers["Referrer-Policy"] == "no-referrer" and headers["X-Frame-Options"] == "DENY"
    assert "script" not in body and "localStorage" not in body and KEY not in body + server.url
    csrf = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    posted = urllib.parse.urlencode({"csrf": csrf, "key": KEY})
    status, _, body = request(server, "POST", body=posted, origin=server.origin)
    assert status == 200 and accepted == [KEY] and KEY not in body
    assert KEY not in "".join(capsys.readouterr())
    assert request(server)[0] == 404


@pytest.mark.parametrize("overrides", [
    {"origin": "https://evil.example"},
    {"origin": None},
    {"host": "evil.example", "origin": "https://evil.example"},
    {"path": "/wrong-session"},
    {"extra": {"Sec-Fetch-Site": "cross-site"}},
])
def test_browser_rejects_csrf_rebinding_and_wrong_sessions(form, overrides):
    server, accepted = form
    values = {"origin": server.origin, **overrides}
    status, _, body = request(server, "POST", body=urllib.parse.urlencode({"csrf": server.csrf, "key": KEY}), **values)
    assert status == 403 and accepted == [] and KEY not in body


def test_browser_body_is_bounded_and_session_expires(form):
    server, accepted = form
    assert request(server, "POST", origin=server.origin, body="x" * 4097)[0] == 400
    assert accepted == []
    server.deadline = time.monotonic() - 1
    assert request(server)[0] == 404


def test_browser_bad_key_can_be_retried_without_reinstall(form):
    server, accepted = form
    original = server.accept
    server.accept = lambda key: (_ for _ in ()).throw(OnboardingProblem("key_rejected", "Try a different key."))
    posted = urllib.parse.urlencode({"csrf": server.csrf, "key": KEY})
    status, _, body = request(server, "POST", body=posted, origin=server.origin)
    assert status == 400 and 'type="password"' in body and server.result is None
    server.accept = original
    assert request(server, "POST", body=posted, origin=server.origin)[0] == 200
    assert accepted == [KEY]


def test_credentials_are_not_written_into_a_project(tmp_path, monkeypatch):
    monkeypatch.setattr("polaris.remote.credentials_path", lambda: tmp_path / "credentials.json")
    with pytest.raises(OnboardingProblem, match="outside the project"):
        auth.activate("https://api.example", project=tmp_path)
    assert not credentials_path().exists()
