"""Conservative removal of this running standalone package, never an arbitrary prefix."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
from collections import defaultdict
from pathlib import Path
from typing import Any

from polaris.integrations._safe import (
    FileSnapshot,
    checked_unlink,
    parent_descriptor,
    read_snapshot,
)
from polaris.onboarding.errors import OnboardingProblem
from polaris.onboarding.installation import _owned, managed_installation, tree_inventory


def _changed() -> OnboardingProblem:
    return OnboardingProblem(
        "installation_changed",
        "Removal refused because owned files are missing, modified or accompanied by unknown files. No automatic cleanup is safe.",
    )


def _snapshot(path: Path, *, limit: int = 20_000_000) -> FileSnapshot:
    value = read_snapshot(path, limit=limit)
    if value is None:
        raise _changed()
    _owned(path, private=True)
    return value


def _record(snapshot: FileSnapshot) -> dict[str, Any]:
    return {"kind": "file", "sha256": hashlib.sha256(snapshot.value).hexdigest(),
            "bytes": len(snapshot.value), "mode": snapshot.mode}


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _remove_entry(parent: int, name: str, relative: str, record: dict[str, Any],
                  entries: dict[str, dict[str, Any]], children: dict[str, list[str]]) -> None:
    before = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if before.st_uid != os.getuid():
        raise _changed()
    kind = record["kind"]
    if kind == "directory":
        if not stat.S_ISDIR(before.st_mode) or stat.S_IMODE(before.st_mode) != record["mode"]:
            raise _changed()
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            if _identity(os.fstat(descriptor)) != _identity(before):
                raise _changed()
            for child in children.get(relative, []):
                child_relative = f"{relative}/{child}" if relative else child
                _remove_entry(descriptor, child, child_relative, entries[child_relative], entries, children)
            if os.listdir(descriptor):
                # Known scratch/quarantine, or a concurrent addition, is never recursively deleted.
                return
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                raise _changed()
            os.rmdir(name, dir_fd=parent)
        finally:
            os.close(descriptor)
        return
    if kind == "link":
        if not stat.S_ISLNK(before.st_mode) or os.readlink(name, dir_fd=parent) != record["target"]:
            raise _changed()
    elif kind == "file":
        if (not stat.S_ISREG(before.st_mode) or before.st_size != record["bytes"]
                or stat.S_IMODE(before.st_mode) != record["mode"]):
            raise _changed()
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb") as stream:
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                raise _changed()
            for chunk in iter(lambda: stream.read(1_048_576), b""):
                digest.update(chunk)
            if _identity(os.fstat(stream.fileno())) != _identity(before):
                raise _changed()
        if digest.hexdigest() != record["sha256"]:
            raise _changed()
    else:
        raise _changed()
    if _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != _identity(before):
        raise _changed()
    os.unlink(name, dir_fd=parent)


def uninstall(*, confirm: bool = False) -> dict[str, Any]:
    installation = managed_installation()
    manager = installation["manager"]
    if manager != "standalone":
        return {
            "status": "package_manager_owned", "manager": manager, "changed": False,
            "next_action": "Use brew uninstall polaris; Theo never removes a Homebrew keg."
            if manager == "homebrew" else
            "Remove theovex-polaris using the Python package manager that installed it.",
        }
    prefix, root = Path(installation["prefix"]), Path(installation["root"])
    home = Path.home().resolve()
    if prefix == home or home.is_relative_to(prefix) or prefix == Path(prefix.anchor):
        raise OnboardingProblem("unsafe_prefix", "Removal cannot target your home or its ancestors.")
    lock_path = prefix / "install.lock"
    _owned(lock_path, private=True)
    with parent_descriptor(lock_path) as parent:
        descriptor = os.open(lock_path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise _changed()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise OnboardingProblem("installation_busy", "Another installation operation is running. No files were removed.") from None
        return _uninstall_locked(prefix, root, release=installation["release"], confirm=confirm)
    finally:
        os.close(descriptor)


def _uninstall_locked(prefix: Path, root: Path, *, release: str, confirm: bool) -> dict[str, Any]:
    if stat.S_IMODE(root.lstat().st_mode) != 0o700:
        raise _changed()
    removal = _snapshot(root / "uninstall-files.json")
    if removal.mode != 0o600:
        raise _changed()
    receipt = json.loads(removal.value)
    if (not isinstance(receipt, dict) or receipt.get("format") != "polaris.theo-removal/1"
            or receipt.get("release") != release or not isinstance(receipt.get("files"), dict)
            or receipt["files"] != tree_inventory(root)):
        raise _changed()
    entries = receipt["files"]
    current = _snapshot(prefix / "current.json", limit=16_384)
    active = json.loads(current.value)
    if current.mode != 0o600 or not isinstance(active, dict) or active.get("format") != "polaris.theo-current/2":
        raise _changed()
    commands: dict[Path, FileSnapshot] = {}
    if active.get("release") == release:
        if not isinstance(active.get("launchers"), dict) or set(active["launchers"]) != {"theo", "polaris"}:
            raise _changed()
        for name in ("theo", "polaris"):
            path = prefix / "bin" / name
            snapshot = _snapshot(path, limit=16_384)
            if snapshot.mode != 0o700 or hashlib.sha256(snapshot.value).hexdigest() != active["launchers"][name]:
                raise _changed()
            commands[path] = snapshot
    summary = {
        "status": "removal_preview", "manager": "standalone", "release": release,
        "root": str(root), "commands": list(map(str, commands)), "changed": False,
        "next_action": "Rerun theo uninstall --yes to remove this unchanged runtime and its active owned commands.",
        "retained": ["project/editor configuration", "credentials", "shell profiles and backups",
                     "older releases", "installer scratch/cache", "quarantined interruptions", "prefix ownership/lock"],
    }
    if not confirm:
        return summary
    entries = {**entries, "uninstall-files.json": _record(removal)}
    children: dict[str, list[str]] = defaultdict(list)
    for relative in sorted(entries):
        path = Path(relative)
        children["" if path.parent == Path(".") else path.parent.as_posix()].append(path.name)
    try:
        for path, snapshot in commands.items():
            checked_unlink(path, snapshot)
        if commands:
            checked_unlink(prefix / "current.json", current)
        with parent_descriptor(root) as parent:
            _remove_entry(parent, root.name, "", {"kind": "directory", "mode": 0o700}, entries, children)
    except (OSError, ValueError, OnboardingProblem):
        raise OnboardingProblem(
            "removal_stopped",
            "Removal stopped after a filesystem change. Some owned files may already be removed; other content was retained. Recover with a verified installer in a new prefix.",
        ) from None
    return {
        **summary, "status": "runtime_removed", "changed": True,
        "next_action": "The selected runtime was removed. Retained profiles, caches, credentials and project setup require separate explicit actions.",
    }
