"""Installed source/notice byte integrity, never legal or native-source approval."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Any

from polaris.review.analyzers.identity import _directory, _read

MANIFEST = "source-packet.json"
MAX_FILES = 20_000
MAX_FILE_BYTES = 128_000_000
MAX_TOTAL_BYTES = 800_000_000


def _path(value: Any) -> str:
    if (not isinstance(value, str) or len(value) > 1024
            or not 1 <= len(value.split("/")) <= 32
            or any(part in ("", ".", "..") or re.fullmatch(r"[A-Za-z0-9_.+@=-]+", part) is None
                   for part in value.split("/"))):
        raise ValueError("Source packet path is not canonical and recipient-relative.")
    return value


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Source packet contains duplicate JSON keys.")
        result[key] = value
    return result


def verify_installed_sources(root: Path, binding: dict[str, Any]) -> dict[str, Any]:
    """Replay the pinned inventory without importing, extracting or executing its files.

    The assembly-time validator checks source references and missing obligations.
    This separate recipient check detects changed/missing/extra bytes and modes,
    including interrupted-install tampering. It cannot make compliance complete.
    """
    if (binding.get("preparationOnly") is not True or binding.get("complianceComplete") is not False
            or binding.get("releaseQualified") is not False):
        raise ValueError("Installed source packet must retain its preparation-only status.")
    raw = _read(root / MANIFEST, 16_000_000)
    if hashlib.sha256(raw).hexdigest() != binding.get("manifestSha256"):
        raise ValueError("Installed source manifest differs from the release binding.")
    manifest = json.loads(raw, object_pairs_hook=_unique)
    if (not isinstance(manifest, dict) or manifest.get("format") != "polaris.source-packet/1"
            or manifest.get("preparationOnly") is not True or manifest.get("complianceComplete") is not False
            or manifest.get("releaseQualified") is not False):
        raise ValueError("Installed source manifest cannot claim completed compliance.")
    rows = manifest.get("files")
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_FILES:
        raise ValueError("Installed source packet requires a bounded file inventory.")
    expected = {MANIFEST: ("file", len(raw), 0o644)}
    folded: dict[str, str] = {MANIFEST: MANIFEST}
    total = 0
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("Invalid source packet inventory entry.")
        name = _path(row.get("path"))
        size, mode = row.get("bytes"), row.get("mode")
        if (type(size) is not int or not 0 <= size <= MAX_FILE_BYTES
                or type(mode) is not int or mode not in (0o644, 0o755)
                or not isinstance(row.get("sha256"), str)
                or re.fullmatch(r"[a-f0-9]{64}", row["sha256"]) is None or name in expected):
            raise ValueError("Invalid or duplicate source packet file binding.")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise ValueError("Source packet exceeds its aggregate byte bound.")
        expected[name] = ("file", size, mode)
        for parent in Path(name).parents:
            if parent == Path("."):
                continue
            key = parent.as_posix()
            if key in expected and expected[key][0] != "directory":
                raise ValueError("Source packet file/directory collision.")
            expected[key] = ("directory", 0, 0)
        for key in (name, *(p.as_posix() for p in Path(name).parents if p != Path("."))):
            if key.casefold() in folded and folded[key.casefold()] != key:
                raise ValueError("Source packet contains case-colliding paths.")
            folded[key.casefold()] = key
    deadline = time.monotonic() + 120

    def inventory() -> dict[str, tuple[str, int, int]]:
        result: dict[str, tuple[str, int, int]] = {}
        count = 0

        def walk(descriptor: int, prefix: str) -> None:
            nonlocal count
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    count += 1
                    if count > (MAX_FILES + 1) * 32 or time.monotonic() >= deadline:
                        raise ValueError("Source packet traversal exceeded its bound.")
                    name = _path(prefix + entry.name)
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        nested = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                         dir_fd=descriptor)
                        try:
                            opened = os.fstat(nested)
                            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                                raise ValueError("Source directory changed during inspection.")
                            walk(nested, name + "/")
                        finally:
                            os.close(nested)
                        result[name] = ("directory", 0, 0)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        result[name] = ("file", info.st_size, stat.S_IMODE(info.st_mode))
                    else:
                        raise ValueError("Installed source packet contains a link or special file.")

        descriptor = _directory(root)
        try:
            walk(descriptor, "")
        finally:
            os.close(descriptor)
        return result

    if inventory() != expected:
        raise ValueError("Installed source packet inventory differs from its release binding.")
    for row in rows:
        if time.monotonic() >= deadline:
            raise ValueError("Source packet verification exceeded its time bound.")
        data = _read(root / row["path"], row["bytes"])
        if hashlib.sha256(data).hexdigest() != row["sha256"]:
            raise ValueError("An installed source or notice file differs from its release binding.")
    if inventory() != expected or _read(root / MANIFEST, 16_000_000) != raw:
        raise ValueError("Installed source packet changed during verification.")
    return {"integrityVerified": True, "includedFiles": len(rows), "includedBytes": total,
            "preparationOnly": True, "complianceComplete": False, "releaseQualified": False}
