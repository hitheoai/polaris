"""Remembering the last check, so the next one can say what was fixed and what is new.

Records live in Git's per-worktree admin directory (`.git/polaris-agent/<worktree>/check/`, see
`polaris.integrations.freshness.state_directory`), which is never tracked or part of a reviewed
snapshot. Only item ids (hex fingerprints) are stored: no source, paths or messages. A missing,
unreadable, oversized or invalid record means "no previous check", never an error, and saving
never raises: remembering is a convenience, so it must never break a check.

One small JSON file per scope key, written atomically through no-follow directory descriptors
(the same helpers as the local review receipt). A folder without Git has no such directory, so
nothing is remembered there.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from pathlib import Path

STATE_FORMAT = "polaris.check-state/1"
MAX_IDS = 5_000
MAX_BYTES = 256_000
# Keys come from `scope_key`: a scope name, plus a digest of the user's selection.
KEY = re.compile(r"[a-z_]{1,32}(?:-[0-9a-f]{16})?")
HEX = re.compile(r"[0-9a-f]{8,64}")


def scope_key(scope: str, detail: str | None = None) -> str:
    """A stable, value-free name for what was checked: the scope, plus a digest of any detail
    the user chose (a revision range or a list of files)."""
    if detail is None:
        return scope
    return f"{scope}-{hashlib.sha256(detail.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}"


def _record(root: Path, key: str) -> Path | None:
    """Where the record for `key` lives, or None for a key that isn't one of ours."""
    if not KEY.fullmatch(key):
        return None
    from polaris.integrations.freshness import state_directory

    return state_directory(root) / "check" / f"{key}.json"


def load_previous(root: Path, key: str) -> list[str] | None:
    """The item ids still open after the last check with this key, or None."""
    from polaris.integrations._safe import IntegrationProblem, read_bytes

    try:
        path = _record(root, key)
        raw = read_bytes(path, limit=MAX_BYTES) if path is not None else None
    except (IntegrationProblem, OSError, ValueError, RuntimeError):
        return None  # outside Git, a symbolic link, too large or unreadable: no previous check
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if not isinstance(data, dict) or data.get("format") != STATE_FORMAT or data.get("key") != key:
        return None
    ids = data.get("ids")
    if (not isinstance(ids, list) or len(ids) > MAX_IDS
            or not all(isinstance(item, str) and HEX.fullmatch(item) for item in ids)):
        return None  # includes the record of a check with too many items to compare
    return sorted(set(ids))


def save(root: Path, key: str, ids: Iterable[str]) -> None:
    """Remember the ids of every open item this check found (`build.finding_ids`: listed or only
    counted in `more`). Never raises.

    More than `MAX_IDS` items can't be compared reliably, so such a check is recorded as not
    comparable: the next check then reports nothing since last check, rather than a wrong diff.
    """
    from polaris.integrations._safe import IntegrationProblem, atomic_write

    try:
        path = _record(root, key)
        if path is None:
            return
        unique = sorted({item for item in ids if isinstance(item, str) and HEX.fullmatch(item)})
        record: dict[str, object] = {"format": STATE_FORMAT, "key": key, "ids": unique}
        content = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(unique) > MAX_IDS or len(content) + 1 > MAX_BYTES:
            record["ids"] = None
            content = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        atomic_write(path, content + b"\n")
    except (IntegrationProblem, OSError, ValueError, RuntimeError):
        return None
