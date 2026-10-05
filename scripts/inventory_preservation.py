"""Prospective byte/metadata preservation, never a retrospective or atomic snapshot claim.

No links are followed. FIFOs, sockets and devices are described without opening them.
Timestamps, ACLs, extended attributes, file flags and external link targets are not covered.
Timestamps/inodes are used only to detect concurrent changes during traversal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import stat
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

FORMAT = "polaris.preservation-inventory/1"
COVERAGE = [
    "entry kind", "permission/special mode bits", "uid", "gid", "link count",
    "regular-file size and SHA256", "literal symlink target", "special-file device number",
]
NOT_COVERED = [
    "timestamps", "ACLs", "extended attributes", "file flags", "external symlink target bytes",
    "atomic filesystem snapshot", "changes occurring and reverting between observations",
]


@dataclass(frozen=True)
class Limits:
    entries: int = 250_000
    file_bytes: int = 8_000_000_000
    total_bytes: int = 200_000_000_000
    depth: int = 128
    seconds: float = 1200

    def __post_init__(self) -> None:
        if any(type(value) is not int or value < 1 for value in (
            self.entries, self.file_bytes, self.total_bytes, self.depth,
        )) or not math.isfinite(self.seconds) or self.seconds <= 0:
            raise ValueError("Inventory bounds must be positive and finite.")


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_rdev)


def _same(before: os.stat_result, after: os.stat_result) -> None:
    if _identity(before) != _identity(after):
        raise ValueError("An inventory entry changed during observation.")


def open_directory(path: Path) -> int:
    """Open every ancestor relative to its descriptor, refusing root/ancestor symlinks."""
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Inventory paths must be absolute without parent traversal.")
    descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _relative(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or value == "." or path.is_absolute() or path.as_posix() != value
            or ".." in path.parts or "\\" in value or "\0" in value):
        raise ValueError("Exclusions must name exact relative subtrees, not globs or parents.")
    return value


def capture(root: Path, *, exclude: Iterable[str] = (), limits: Limits | None = None) -> dict[str, Any]:
    limits = limits if limits is not None else Limits()
    exclusions = sorted({_relative(value) for value in exclude})
    entries: dict[str, dict[str, Any]] = {}
    total = 0
    deadline = time.monotonic() + limits.seconds

    def bounded() -> None:
        if time.monotonic() >= deadline:
            raise ValueError("Inventory exceeded its time bound.")

    def observe(parent: int, name: str, relative: str, depth: int) -> None:
        nonlocal total
        bounded()
        if any(relative == value or relative.startswith(value + "/") for value in exclusions):
            return
        if len(entries) >= limits.entries or depth > limits.depth:
            raise ValueError("Inventory exceeded its entry or depth bound.")
        before = os.stat(name, dir_fd=parent, follow_symlinks=False)
        item: dict[str, Any] = {
            "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
            "gid": before.st_gid, "links": before.st_nlink,
        }
        entries[relative] = item
        if stat.S_ISLNK(before.st_mode):
            item.update(kind="link", target=os.readlink(name, dir_fd=parent))
        elif stat.S_ISDIR(before.st_mode):
            item["kind"] = "directory"
            descriptor = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent,
            )
            try:
                _same(before, os.fstat(descriptor))
                names = []
                with os.scandir(descriptor) as iterator:
                    for entry in iterator:
                        bounded()
                        names.append(entry.name)
                        if len(names) > limits.entries:
                            raise ValueError("Directory listing exceeded its entry bound.")
                for child in sorted(names):
                    observe(descriptor, child, child if relative == "." else relative + "/" + child, depth + 1)
                _same(before, os.fstat(descriptor))
            finally:
                os.close(descriptor)
        elif stat.S_ISREG(before.st_mode):
            if before.st_size > limits.file_bytes or total + before.st_size > limits.total_bytes:
                raise ValueError("Inventory exceeded its byte bound.")
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            with os.fdopen(descriptor, "rb") as stream:
                _same(before, os.fstat(stream.fileno()))
                digest, size = hashlib.sha256(), 0
                for chunk in iter(lambda: stream.read(1_048_576), b""):
                    bounded()
                    size += len(chunk)
                    if size > before.st_size:
                        raise ValueError("An inventory file grew during observation.")
                    digest.update(chunk)
                _same(before, os.fstat(stream.fileno()))
                if size != before.st_size:
                    raise ValueError("An inventory file shrank during observation.")
            total += size
            item.update(kind="file", bytes=size, sha256=digest.hexdigest())
        else:
            kind = {
                stat.S_IFIFO: "fifo", stat.S_IFSOCK: "socket",
                stat.S_IFCHR: "character-device", stat.S_IFBLK: "block-device",
            }.get(stat.S_IFMT(before.st_mode))
            if kind is None:
                raise ValueError("Unknown special-file kind.")
            item.update(kind=kind, device=before.st_rdev)
        _same(before, os.stat(name, dir_fd=parent, follow_symlinks=False))

    descriptor = open_directory(root)
    try:
        observe(descriptor, ".", ".", 0)
    finally:
        os.close(descriptor)
    return {
        "format": FORMAT, "root": str(root), "exclusions": exclusions,
        "coverage": COVERAGE, "notCovered": NOT_COVERED,
        "entries": entries, "regularFileBytes": total,
    }


def compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    if (before.get("format") != FORMAT or after.get("format") != FORMAT
            or any(before.get(key) != after.get(key) for key in ("root", "exclusions", "coverage", "notCovered"))
            or before.get("coverage") != COVERAGE or before.get("notCovered") != NOT_COVERED
            or not isinstance(before.get("entries"), dict) or not isinstance(after.get("entries"), dict)):
        raise ValueError("Only matching inventory scopes may be compared.")
    old, new = before["entries"], after["entries"]
    changes = []
    for path in sorted(old.keys() | new.keys()):
        if path not in old:
            reason = "added"
        elif path not in new:
            reason = "removed"
        elif old[path] != new[path]:
            reason = "type_changed" if old[path].get("kind") != new[path].get("kind") else "changed"
        else:
            continue
        changes.append({"path": path, "reason": reason})
    return {"preserved": not changes, "changes": changes, "entriesCompared": len(old)}


def write_new(path: Path, value: Any) -> None:
    parent = open_directory(path.parent)
    try:
        descriptor = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent,
        )
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True, indent=2)
            stream.write("\n")
    finally:
        os.close(parent)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("--exclude", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = capture(args.root, exclude=args.exclude)
        write_new(args.output, result)
    except (OSError, ValueError):
        raise SystemExit("Preservation inventory incomplete; no preservation claim is made.") from None
    print(json.dumps({"entries": len(result["entries"]), "regularFileBytes": result["regularFileBytes"]}))


if __name__ == "__main__":
    main()
