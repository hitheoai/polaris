from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from polaris.errors import PolarisInputError

MAX_PAYLOAD_BYTES = 1_048_576
MAX_DEPTH = 16
MAX_NODES = 50_000


def check_structure(value: Any) -> None:
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_DEPTH or nodes > MAX_NODES:
            raise PolarisInputError("payload_limit")
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise PolarisInputError("invalid_input")
            pending.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, float):
            if not math.isfinite(item):
                raise PolarisInputError("invalid_input")
        elif item is not None and not isinstance(item, (str, int, bool)):
            raise PolarisInputError("invalid_input")


def canonical_bytes(value: Any) -> bytes:
    """Python-contract canonical JSON; not an assertion of RFC 8785 compatibility."""
    try:
        return json.dumps(
            value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise PolarisInputError("invalid_input") from exc


def digest_bytes(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def digest_text(content: str) -> str:
    try:
        return digest_bytes(content.encode("utf-8"))
    except UnicodeError as exc:
        raise PolarisInputError("invalid_input") from exc


def digest_json(value: Any) -> str:
    return digest_bytes(canonical_bytes(value))


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolarisInputError("invalid_input")
        result[key] = value
    return result


def _invalid_constant(_: str) -> None:
    raise PolarisInputError("invalid_input")


def load_json(content: str | bytes, *, max_bytes: int = MAX_PAYLOAD_BYTES) -> Any:
    try:
        raw = content.encode("utf-8") if isinstance(content, str) else content
        if len(raw) > max_bytes:
            raise PolarisInputError("payload_limit")
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_invalid_constant
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PolarisInputError("invalid_input") from exc
    check_structure(value)
    return value
