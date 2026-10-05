"""Conservative output guards, not a general-purpose DLP or authorization system."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import BaseModel

from polaris.engineering.errors import EngineeringError

_SENSITIVE_PARTS = frozenset({".git", ".hg", ".svn", ".ssh", ".aws", ".gnupg"})
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"),
    re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}"),
    re.compile(r"(?i)\bhttps?://[^/\s:@]+:[^/\s@]+@"),
    re.compile(
        r"""(?ix)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|password|passwd)
        ["']?\s*[:=]\s*["']([^"'\r\n]{8,})["']"""
    ),
    re.compile(r"(?i)[?&](?:api[_-]?key|token|secret|password)=[^&#\s]{4,}"),
)


def relative_path(value: str, *, allow_root: bool = False) -> str:
    """Require the exact POSIX spelling; never normalize an untrusted path into scope."""
    if not isinstance(value, str) or not value or len(value) > 512:
        raise EngineeringError("invalid_path")
    if allow_root and value == ".":
        return value
    if (
        value.startswith(("/", "~"))
        or "\\" in value
        or ":" in value
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise EngineeringError("invalid_path")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise EngineeringError("invalid_path")
    if any(
        part.lower() in _SENSITIVE_PARTS
        or part.lower() == ".env"
        or part.lower().startswith(".env.")
        or part.lower() in {"id_rsa", "id_ed25519", "credentials.json"}
        or part.lower().endswith((".pem", ".key", ".p12", ".pfx"))
        for part in parts
    ):
        raise EngineeringError("unsafe_file")
    return value


def utf8_bytes(value: str) -> bytes:
    if not isinstance(value, str) or "\x00" in value:
        raise EngineeringError("invalid_input")
    try:
        return value.encode("utf-8")
    except UnicodeError:
        raise EngineeringError("invalid_input") from None


def contains_secret(value: str, *, known_secrets: Sequence[str] = ()) -> bool:
    if any(secret and secret in value for secret in known_secrets):
        return True
    return any(pattern.search(value) is not None for pattern in _SECRET_PATTERNS)


def guard_output(value: Any, *, known_secrets: Sequence[str] = ()) -> None:
    """Reject rather than echo or persist detected secrets; never include excerpts in errors."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json", warnings=False)
    pending = [value]
    nodes = 0
    while pending:
        item = pending.pop()
        nodes += 1
        if nodes > 50_000:
            raise EngineeringError("payload_limit")
        if isinstance(item, str):
            utf8_bytes(item)
            if contains_secret(item, known_secrets=known_secrets):
                raise EngineeringError("secret_detected")
        elif isinstance(item, Mapping):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, (tuple, list)):
            pending.extend(item)
