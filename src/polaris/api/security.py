"""API keys, per-key rate limits, the bounded work queue and code-free usage records.

Keys are 256-bit random secrets shown once at creation. Only a salted HMAC-SHA256 of each key
is stored: slow password hashes protect guessable passwords, not random keys, and a fast
check keeps every request cheap.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from pydantic import Field, ValidationError

from polaris.contract import StrictModel
from polaris.errors import PolarisError
from polaris.jsonio import load_json

KEY_FILE_FORMAT: Literal["polaris.api-keys/0.1.0"] = "polaris.api-keys/0.1.0"
KEY_PATTERN = re.compile(r"^plk_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$")
ENTRY_PATTERN = re.compile(r"^([0-9a-f]{8}):([0-9a-f]{32}):([0-9a-f]{64})$")
T = TypeVar("T")


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class KeyProblem(ValueError):
    """A key file or POLARIS_API_KEYS value that can't be used; the message says why."""


class ApiKey(StrictModel):
    key_id: Annotated[str, Field(pattern=r"^[0-9a-f]{8}$")]
    name: Annotated[str, Field(min_length=1, max_length=64)]
    salt: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    digest: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    created: str
    rate_per_minute: Annotated[float, Field(ge=0, le=100_000)] | None = None


class KeyFile(StrictModel):
    format: Literal["polaris.api-keys/0.1.0"] = KEY_FILE_FORMAT
    algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    keys: list[ApiKey] = Field(default_factory=list)


def _digest(salt_hex: str, raw: str) -> str:
    return hmac.new(bytes.fromhex(salt_hex), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def new_key(name: str, *, rate_per_minute: float | None = None) -> tuple[str, ApiKey]:
    """Return (raw key, stored record). The raw key must be shown once and never stored."""
    key_id = secrets.token_hex(4)
    raw = f"plk_{key_id}_{secrets.token_urlsafe(32)}"
    salt = secrets.token_hex(16)
    record = ApiKey(key_id=key_id, name=name, salt=salt, digest=_digest(salt, raw),
                    created=utc_now(), rate_per_minute=rate_per_minute)
    return raw, record


class KeyStore:
    """Verifies presented keys against salted hashes; never holds a raw key."""

    def __init__(self, keys: Iterable[ApiKey]) -> None:
        self.keys = {record.key_id: record for record in keys}

    def __len__(self) -> int:
        return len(self.keys)

    def verify(self, presented: str) -> ApiKey | None:
        match = KEY_PATTERN.match(presented)
        record = self.keys.get(match.group(1)) if match else None
        # Compare even for unknown IDs so timing doesn't reveal which IDs exist.
        salt, expected = (record.salt, record.digest) if record else ("0" * 32, "0" * 64)
        valid = hmac.compare_digest(_digest(salt, presented), expected)
        return record if valid and record is not None else None

    @classmethod
    def read(cls, path: Path) -> KeyStore:
        return cls(read_key_file(path).keys)

    @classmethod
    def from_environment(cls, value: str) -> KeyStore:
        """POLARIS_API_KEYS: a key file path, or comma-separated `id:salt:digest` entries."""
        value = value.strip()
        if "plk_" in value:
            raise KeyProblem(
                "POLARIS_API_KEYS must hold key hashes from `polaris serve keys create` "
                "(or a key file path), never the keys themselves."
            )
        if value and not ENTRY_PATTERN.match(value.split(",")[0].strip()):
            return cls.read(Path(value).expanduser())
        records = []
        for position, entry in enumerate(part.strip() for part in value.split(",") if part.strip()):
            match = ENTRY_PATTERN.match(entry)
            if match is None:
                raise KeyProblem(f"POLARIS_API_KEYS entry {position + 1} isn't in the id:salt:hash form.")
            records.append(ApiKey(key_id=match.group(1), name=f"env-{match.group(1)}",
                                  salt=match.group(2), digest=match.group(3), created="environment"))
        if not records:
            raise KeyProblem("POLARIS_API_KEYS is empty.")
        return cls(records)


def read_key_file(path: Path) -> KeyFile:
    """Read a key file. Links are fine here (secret mounts use them); writes refuse them."""
    try:
        return KeyFile.model_validate(load_json(path.read_bytes()))
    except FileNotFoundError as exc:
        raise KeyProblem(f"No key file at {path}. Create one with `polaris serve keys create`.") from exc
    except (OSError, PolarisError, ValidationError) as exc:
        raise KeyProblem(f"{path} isn't a valid Polaris key file.") from exc


def write_key_file(path: Path, keys: KeyFile) -> None:
    """Write atomically, readable only by the owner (the file holds hashes, not keys)."""
    if path.is_symlink():
        raise KeyProblem(f"{path} is a symbolic link; refusing to write through it.")
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(keys.model_dump(mode="json"), indent=2) + "\n"
    handle, temporary = tempfile.mkstemp(prefix=".polaris-keys-", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


class RateLimiter:
    """A token bucket per key: `rate_per_minute` refill and `burst` capacity. 0 means unlimited."""

    def __init__(self, rate_per_minute: float, burst: int,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate_per_minute = rate_per_minute
        self.burst = max(1, burst)
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def acquire(self, key_id: str, rate_per_minute: float | None = None) -> float:
        """0.0 when the request may proceed; otherwise the seconds until it would."""
        rate = self.rate_per_minute if rate_per_minute is None else rate_per_minute
        if rate <= 0:
            return 0.0
        per_second = rate / 60
        with self._lock:
            now = self._clock()
            tokens, updated = self._buckets.get(key_id, (float(self.burst), now))
            tokens = min(float(self.burst), tokens + (now - updated) * per_second)
            if tokens >= 1:
                self._buckets[key_id] = (tokens - 1, now)
                return 0.0
            self._buckets[key_id] = (tokens, now)
            return (1 - tokens) / per_second


class QueueFull(Exception):
    """More requests are waiting than the server allows."""


class WorkQueue:
    """At most `workers` jobs run at once and at most `depth` wait; beyond that callers get 429.

    Jobs run in worker threads so the event loop stays responsive.
    """

    def __init__(self, workers: int, depth: int) -> None:
        self.workers = max(1, workers)
        self.depth = max(0, depth)
        self.admitted = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._slots: asyncio.Semaphore | None = None

    async def run(self, job: Callable[[], T]) -> T:
        import anyio.to_thread

        if self.admitted >= self.workers + self.depth:
            raise QueueFull
        loop = asyncio.get_running_loop()
        if self._slots is None or self._loop is not loop:
            self._loop, self._slots = loop, asyncio.Semaphore(self.workers)
        self.admitted += 1
        try:
            async with self._slots:
                return await anyio.to_thread.run_sync(job)
        finally:
            self.admitted -= 1


@dataclass
class Usage:
    requests: int = 0
    reviews: int = 0
    assessments: int = 0
    files_reviewed: int = 0
    functions_total: int = 0
    functions_assessed: int = 0
    rejected: int = 0


@dataclass
class UsageTracker:
    """Per-key counters, optionally appended to a JSON-lines file. Never records code or paths."""

    path: Path | None = None
    started: str = field(default_factory=utc_now)
    _usage: dict[str, Usage] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def __post_init__(self) -> None:
        if self.path is not None and self.path.is_symlink():
            raise KeyProblem(f"{self.path} is a symbolic link; refusing to write usage through it.")

    def record(self, key_id: str, *, method: str, endpoint: str, status: int, elapsed_ms: float,
               work: Mapping[str, Any] | None = None) -> None:
        work = dict(work or {})
        with self._lock:
            usage = self._usage.setdefault(key_id, Usage())
            usage.requests += 1
            usage.rejected += int(status >= 400)
            usage.reviews += int(work.get("reviews", 0))
            usage.assessments += int(work.get("assessments", 0))
            usage.files_reviewed += int(work.get("files_reviewed", 0))
            usage.functions_total += int(work.get("functions_total", 0))
            usage.functions_assessed += int(work.get("functions_assessed", 0))
            if self.path is not None:
                line = {"time": utc_now(), "key_id": key_id, "method": method, "endpoint": endpoint,
                        "status": status, "elapsed_ms": round(elapsed_ms, 2), **work}
                with self.path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(line, sort_keys=True) + "\n")

    def usage(self, key_id: str) -> Usage:
        with self._lock:
            return Usage(**asdict(self._usage.get(key_id, Usage())))


def summarize_usage(path: Path) -> dict[str, Usage]:
    """Totals per key from a usage log written by `polaris serve --usage-log`."""
    totals: dict[str, Usage] = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            if not line.strip():
                continue
            entry = json.loads(line)
            usage = totals.setdefault(str(entry.get("key_id", "unknown")), Usage())
            usage.requests += 1
            usage.rejected += int(int(entry.get("status", 0)) >= 400)
            for name in ("reviews", "assessments", "files_reviewed", "functions_total",
                         "functions_assessed"):
                setattr(usage, name, getattr(usage, name) + int(entry.get(name, 0)))
    return totals
