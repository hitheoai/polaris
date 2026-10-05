from __future__ import annotations

import http.client
import io
import json
import traceback
import urllib.error
from types import SimpleNamespace

import pytest

from polaris.client import (
    MAX_ACCOUNT_RESPONSE_BYTES,
    PolarisAPIError,
    PolarisClient,
)


@pytest.mark.parametrize("url", [
    "https://user:private-value@api.example",
    "https://user@api.example",
    "https://api.example?key=private-value",
    "https://api.example?",
    "https://api.example#private-value",
    "https://api.example#",
    "https://api.example\\@elsewhere.example",
    " https://api.example",
    "https://api.example\n",
    "https://api.example/\x00",
    "https://api.example:0",
    "https://api.example:99999",
    "https://[broken",
    "file:///private-value",
])
def test_api_url_rejection_does_not_echo_input(url):
    with pytest.raises(ValueError) as error:
        PolarisClient(url, api_key="synthetic-test-token")
    assert "private-value" not in str(error.value)
    assert url not in str(error.value)


@pytest.mark.parametrize("url", [
    "https://api.example",
    "https://api.example/prefix/",
    "http://127.0.0.1:8780",
    "http://[::1]:8780",
    "http://localhost:8780",
])
def test_safe_api_addresses_remain_usable(url):
    assert PolarisClient(url, api_key="synthetic-test-token").base_url == url.rstrip("/")


@pytest.mark.parametrize("value", [-1, 0, float("nan"), float("inf"), 601])
def test_transport_timeout_is_finite_and_bounded(value):
    with pytest.raises(ValueError, match="timeout"):
        PolarisClient(timeout=value)


@pytest.mark.parametrize("key", ["two words", "line\nbreak", "tab\tkey", "not-ascii-ñ", "x" * 4097])
def test_invalid_key_is_rejected_without_echo(key):
    with pytest.raises(ValueError) as error:
        PolarisClient("https://api.example", api_key=key)
    assert key not in str(error.value)


@pytest.mark.parametrize("code", ["unauthorized", "private-value", ["private-value"]])
def test_error_bodies_cannot_echo_credentials_or_escape_sequences(code):
    error = PolarisClient._error(
        401,
        json.dumps({"code": code, "message": "Authorization: Bearer private-value\x1b[2J",
                    "retryable": "yes"}).encode(),
        {},
    )
    assert "private-value" not in str(error)
    assert "\x1b" not in str(error)
    assert error.code in ("unauthorized", "http_error")
    assert not error.retryable


@pytest.mark.parametrize("exception", [
    urllib.error.URLError("private-value from an untrusted proxy"),
    http.client.BadStatusLine("private-value from a malformed response"),
    http.client.HTTPException("private-value from a protocol failure"),
    OSError("private-value from a network failure"),
])
def test_network_failure_hides_underlying_credentials_and_exception_context(exception):
    client = PolarisClient("https://api.example", api_key="synthetic-test-token")

    def fail(*args, **kwargs):
        raise exception

    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(PolarisAPIError) as error:
        client.models()
    assert error.value.code == "connection_failed"
    assert "private-value" not in "".join(traceback.format_exception(error.value))


class Response(io.BytesIO):
    status = 200
    headers = {}

@pytest.mark.parametrize("error_response", [False, True])
def test_response_read_failures_are_redacted_and_closed(error_response):
    class BrokenResponse(Response):
        def read(self, *args):
            raise http.client.BadStatusLine("private-value from response bytes")

    stream = BrokenResponse(b"")

    def open_response(*args, **kwargs):
        if error_response:
            raise urllib.error.HTTPError("https://api.example", 401, "private-value", {}, stream)
        return stream

    client = PolarisClient("https://api.example")
    client._opener = SimpleNamespace(open=open_response)
    with pytest.raises(PolarisAPIError) as error:
        client.usage()
    assert error.value.code == "connection_failed"
    assert "private-value" not in "".join(traceback.format_exception(error.value))
    assert stream.closed


def test_account_response_is_bounded_and_closed():
    response = Response(b"x" * (MAX_ACCOUNT_RESPONSE_BYTES + 2))
    client = PolarisClient("https://api.example")
    client._opener = SimpleNamespace(open=lambda *args, **kwargs: response)
    with pytest.raises(PolarisAPIError) as error:
        client.models()
    assert error.value.code == "response_too_large"
    assert response.closed


def test_error_response_is_also_bounded_and_closed():
    stream = io.BytesIO(b"x" * (MAX_ACCOUNT_RESPONSE_BYTES + 2))

    def fail(*args, **kwargs):
        raise urllib.error.HTTPError("https://api.example", 401, "private-value", {}, stream)

    client = PolarisClient("https://api.example")
    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(PolarisAPIError) as error:
        client.usage()
    assert error.value.code == "response_too_large"
    assert "private-value" not in str(error.value)
    assert stream.closed


def test_redirect_response_never_becomes_a_success():
    response = Response(b'{"message":"private-value"}')
    response.status = 302
    client = PolarisClient("https://api.example")
    client._opener = SimpleNamespace(open=lambda *args, **kwargs: response)
    with pytest.raises(PolarisAPIError) as error:
        client.models()
    assert error.value.code == "redirect_refused"
    assert "private-value" not in str(error.value)


def test_retry_metadata_has_a_small_numeric_bound():
    body = b'{"code":"rate_limited","retryable":true}'
    assert PolarisClient._error(429, body, {"Retry-After": "999999"}).retry_after == 60.0
    assert PolarisClient._error(429, body, {"Retry-After": "9" * 10000}).retry_after is None
    assert PolarisClient._error(401, body, {}).retryable is False
    assert PolarisClient._error(429, body, {"Retry-After": "2"}).retryable is True
