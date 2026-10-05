"""The hosted Polaris model: sign in once and reviews use it, while almost everything stays local.

Parsing, the prefilter that finds functions with SQL or process calls, the static notes, the rules
and the report all run on your machine. Only the assessment requests for those candidate functions
are sent: each one holds the function's code (and its previous version when it changed), its file
path and line, the static data-flow notes and your policy statements. Other code never leaves the
machine.

API keys come from `POLARIS_API_KEY` (with an optional `POLARIS_API_URL`) or from
`polaris login`, which stores them in ~/.polaris/credentials.json, readable only by you.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import stat
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal
from urllib.parse import urlsplit

from pydantic import ValidationError

from polaris.contract import (
    AssessmentRequest,
    AssessmentResponse,
    ErrorResponse,
    RuntimeIdentity,
    parse_request,
)
from polaris.errors import PolarisError
from polaris.review.loader import polaris_home

if TYPE_CHECKING:
    from polaris.client import PolarisClient

DEFAULT_API_URL = "https://api.polaris.theovex.com"
BATCH_ITEMS = 32  # the server accepts up to 64 requests per call
BATCH_BYTES = 2 * 1024 * 1024  # stay well below the server's body limit (5 MiB by default)
RETRIES = 3
MAX_WAIT_SECONDS = 10.0
PAUSE_AFTER_CONNECTION_FAILURE = 30.0  # don't wait for a timeout per batch while the API is down
ModelSource = Literal["auto", "local", "remote"]
Problem = Literal["not_signed_in", "remote_unavailable"]
NOT_SIGNED_IN = "Not signed in to the hosted Polaris model. Run `polaris login`, or set POLARIS_API_KEY."
def normalize_api_url(value: str) -> str:
    """Canonical credential-free origin; HTTPS or literal loopback HTTP, never a default."""
    message = "Use a credential-free https:// API origin without paths, queries or fragments."
    if (not isinstance(value, str) or not 1 <= len(value) <= 2048 or not value.isascii()
            or any(ord(character) < 33 or ord(character) > 126 for character in value)
            or any(character in value for character in ("\\", "?", "#", "%"))):
        raise ValueError(message)
    try:
        parts = urlsplit(value)
        if (parts.scheme not in ("http", "https") or not parts.netloc or not parts.hostname
                or parts.username is not None or parts.password is not None or parts.path not in ("", "/")):
            raise ValueError(message)
        authority = parts.netloc
        if authority.startswith("["):
            end = authority.index("]")
            suffix = authority[end + 1:]
            if suffix and (not suffix.startswith(":") or not suffix[1:].isdigit()):
                raise ValueError(message)
            address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.IPv6Address(parts.hostname)
            host = f"[{address.compressed}]"
            loopback = address.is_loopback
        else:
            if "[" in authority or "]" in authority or authority.count(":") > 1:
                raise ValueError(message)
            if ":" in authority and not authority.rsplit(":", 1)[1].isdigit():
                raise ValueError(message)
            name = parts.hostname.lower()
            try:
                address = ipaddress.IPv4Address(name)
            except ValueError:
                if (len(name) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                           for label in name.split("."))):
                    raise ValueError(message) from None
                host, loopback = name, False
            else:
                host, loopback = str(address), address.is_loopback
        port = parts.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError(message)
        if parts.scheme == "http" and not loopback:
            raise ValueError(message)
        if port == (443 if parts.scheme == "https" else 80):
            port = None
        return f"{parts.scheme}://{host}" + (f":{port}" if port is not None else "")
    except (ValueError, IndexError):
        raise ValueError(message) from None


class RemoteUnavailable(RuntimeError):
    """The hosted model can't be used: not signed in, unreachable, or the key was refused."""

    def __init__(self, problem: Problem, message: str) -> None:
        super().__init__(message)
        self.problem = problem


@dataclass(frozen=True)
class Credentials:
    api_url: str
    api_key: str = ""
    source: Literal["environment", "file"] = "file"

    def __repr__(self) -> str:  # never print the key
        try:
            address = normalize_api_url(self.api_url)
        except ValueError:
            address = "<invalid endpoint>"
        return f"Credentials(api_url={address!r}, source={self.source!r})"


def credentials_path() -> Path:
    return polaris_home() / "credentials.json"


def load_credentials() -> Credentials | None:
    """Legacy env precedence, or explicitly file-only credentials pinned by Theo's connector."""
    file_only = os.environ.get("POLARIS_CREDENTIAL_SOURCE") == "file"
    key = "" if file_only else os.environ.get("POLARIS_API_KEY", "").strip()
    if key:
        return Credentials(os.environ.get("POLARIS_API_URL", "").strip() or DEFAULT_API_URL, key, "environment")
    path = credentials_path()
    try:
        from polaris.integrations._safe import read_bytes

        content = read_bytes(path, limit=16_384)
        if content is None:
            return None
        info = path.stat()
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            return None
        data = json.loads(content)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    saved, url = data.get("api_key"), data.get("api_url")
    if not isinstance(saved, str) or not saved.strip():
        return None
    address = url.strip() if isinstance(url, str) and url.strip() else DEFAULT_API_URL
    if file_only:
        from polaris.onboarding.auth import endpoint
        from polaris.onboarding.errors import OnboardingProblem

        expected = os.environ.get("POLARIS_EXPECTED_API_URL")
        try:
            if not expected or not isinstance(url, str) or endpoint(address) != endpoint(expected):
                return None
        except OnboardingProblem:
            return None
    return Credentials(address, saved.strip(), "file")


def save_credentials(api_url: str, api_key: str) -> Path:
    """Write the credentials file atomically with owner-only permissions."""
    from polaris.integrations._safe import (
        IntegrationProblem,
        atomic_write,
        no_symlinks,
        parent_descriptor,
    )
    from polaris.onboarding.auth import validate_key

    api_url = normalize_api_url(api_url)
    path = credentials_path()
    try:
        no_symlinks(path)
        validate_key(api_key)
        with parent_descriptor(path, create=True):
            info = path.parent.stat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o022):
                raise OSError("The credential directory must be owned and writable only by your user.")
        atomic_write(path, (json.dumps({"api_url": api_url, "api_key": api_key}) + "\n").encode())
    except IntegrationProblem:
        raise OSError("The credential destination is unsafe or a symbolic link; it was not replaced.") from None
    return path


def delete_credentials() -> bool:
    from polaris.integrations._safe import parent_descriptor
    path = credentials_path()
    try:
        with parent_descriptor(path) as parent:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise OSError("The credential file is not a user-owned regular file.")
            os.unlink(path.name, dir_fd=parent)
            return True
    except FileNotFoundError:
        return False


def use_remote(source: ModelSource, model: str | Path | None = None) -> bool:
    """Whether to use the hosted model.

    "remote": always. "local": never. "auto": when signed in, unless a local model was named
    with --model or POLARIS_MODEL.
    """
    if source == "remote":
        return True
    if source == "local" or model or os.environ.get("POLARIS_MODEL"):
        return False
    return load_credentials() is not None


def connect(*, timeout: float = 60.0) -> RemoteBackend:
    """The hosted model for the saved credentials. Raises RemoteUnavailable."""
    credentials = load_credentials()
    if credentials is None:
        if os.environ.get("POLARIS_CREDENTIAL_SOURCE") == "file":
            raise RemoteUnavailable("not_signed_in", "The private activation does not match this project's approved API origin. Rerun `theo setup --api-url` for this project; no credentials were sent.")
        raise RemoteUnavailable("not_signed_in", NOT_SIGNED_IN)
    return RemoteBackend(credentials, timeout=timeout)


@dataclass(frozen=True)
class _Point:
    evaluation_risk_threshold: float


@dataclass(frozen=True)
class _Profile:
    checks: Mapping[str, _Point]


Item = tuple[int, dict[str, Any]]


def _chunks(items: list[Item]) -> list[list[Item]]:
    """Consecutive groups of at most BATCH_ITEMS requests and (roughly) BATCH_BYTES."""
    groups: list[list[Item]] = []
    current: list[Item] = []
    size = 0
    for item in items:
        length = len(json.dumps(item[1], ensure_ascii=False).encode("utf-8"))
        if current and (len(current) >= BATCH_ITEMS or size + length > BATCH_BYTES):
            groups.append(current)
            current, size = [], 0
        current.append(item)
        size += length
    if current:
        groups.append(current)
    return groups


class RemoteBackend:
    """A review model whose assessments run on a Polaris API server.

    It has what the review engine needs from a local model (identity, supported checks and flag
    thresholds) plus `assess_many`, which sends locally built requests in batches.
    """

    remote = True

    def __init__(self, credentials: Credentials, *, timeout: float = 60.0,
                 client: PolarisClient | None = None) -> None:
        from polaris.client import PolarisAPIError, PolarisClient

        self.api_url = credentials.api_url.rstrip("/")
        self._paused_until = 0.0
        try:
            self.client = client or PolarisClient(self.api_url, api_key=credentials.api_key, timeout=timeout)
            status = self.client.models().model
        except ValidationError as exc:
            raise RemoteUnavailable("remote_unavailable", f"{self.api_url} didn't answer like a Polaris API, or "
                                    "runs a version this Polaris can't use. Update Polaris.") from exc
        except ValueError as exc:  # an unusable address, such as http:// to another machine
            raise RemoteUnavailable("remote_unavailable", str(exc)) from exc
        except PolarisAPIError as exc:
            if exc.status == 401:
                raise RemoteUnavailable("remote_unavailable", f"The Polaris API at {self.api_url} didn't accept "
                                        "your API key. Run `polaris login` again.") from exc
            raise RemoteUnavailable("remote_unavailable", exc.message) from exc
        if not status.loaded or status.identity is None:
            raise RemoteUnavailable("remote_unavailable",
                                    f"The Polaris API at {self.api_url} has no model right now.")
        self.identity: RuntimeIdentity = status.identity
        self.supported_checks = frozenset(status.supported_checks)
        self.profile = _Profile({check: _Point(value) for check, value in status.flag_thresholds.items()})

    def assess_many(self, values: Sequence[AssessmentRequest | dict[str, Any] | str | bytes], *,
                    batch_size: int = 16) -> list[AssessmentResponse | ErrorResponse]:
        """One envelope per request, in order. Invalid requests are answered here, as locally;
        transport failures become error envelopes."""
        del batch_size  # the server batches model work itself
        results: list[AssessmentResponse | ErrorResponse | None] = [None] * len(values)
        items: list[Item] = []
        for index, value in enumerate(values):
            try:
                items.append((index, parse_request(value).model_dump(mode="json")))
            except PolarisError as exc:
                results[index] = exc.as_response()
        for chunk in _chunks(items):
            for (index, _), response in zip(chunk, self._send([item for _, item in chunk]), strict=True):
                results[index] = response
        answered = [response for response in results if response is not None]
        assert len(answered) == len(values)
        return answered

    def assess_envelope(self, value: AssessmentRequest | dict[str, Any] | str | bytes) -> AssessmentResponse | ErrorResponse:
        return self.assess_many([value])[0]

    def _send(self, chunk: list[dict[str, Any]]) -> list[AssessmentResponse | ErrorResponse]:
        from polaris.client import PolarisAPIError

        if time.monotonic() < self._paused_until:
            message = f"The Polaris API at {self.api_url} couldn't be reached a moment ago; try again shortly."
            return [_failure(item, message, retryable=True) for item in chunk]
        for attempt in range(RETRIES):
            try:
                results = self.client.assess_batch(chunk)
                if len(results) != len(chunk):
                    raise PolarisAPIError(0, "invalid_response", "It returned the wrong number of results.")
                return results
            except PolarisAPIError as exc:
                if exc.retryable and attempt + 1 < RETRIES:
                    time.sleep(min(exc.retry_after or float(attempt + 1), MAX_WAIT_SECONDS))
                    continue
                if exc.code == "connection_failed":
                    self._paused_until = time.monotonic() + PAUSE_AFTER_CONNECTION_FAILURE
                retryable = exc.retryable or exc.code == "connection_failed"
                return [_failure(item, f"The Polaris API couldn't assess this: {exc.message}", retryable=retryable)
                        for item in chunk]
            except ValueError:  # a response that doesn't match the contract
                message = "The Polaris API sent a response this version of Polaris can't read; update Polaris."
                return [_failure(item, message, retryable=False) for item in chunk]
        raise AssertionError("unreachable")


def _failure(item: Mapping[str, Any], message: str, *, retryable: bool) -> ErrorResponse:
    request_id = item.get("request_id")
    try:
        return ErrorResponse(request_id=request_id if isinstance(request_id, str) else None, category="runtime",
                             code="model_unavailable", message=message, retryable=retryable)
    except ValueError:
        return ErrorResponse(category="runtime", code="model_unavailable", message=message, retryable=retryable)
