"""Private receipts and conservative recovery; receipts never prove a live editor connection."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from polaris.integrations._safe import (
    IntegrationProblem,
    atomic_write,
    no_symlinks,
    parent_descriptor,
    read_bytes,
)
from polaris.onboarding.errors import OnboardingProblem

STATE_FORMAT = "polaris.theo-state/1"


def home() -> Path:
    release = Path(sys.prefix).absolute().parent
    if Path(sys.prefix).name == "app" and release.name.startswith("theo-") and (release / "install-receipt.json").is_file():
        return release.parent.parent / "state"
    return Path.home() / ".polaris" / "theo"


def project_root(value: Path) -> Path:
    try:
        root = no_symlinks(value.expanduser().absolute())
    except IntegrationProblem as exc:
        raise OnboardingProblem("unsafe_project", "Project paths must not contain symbolic links.") from exc
    # Resolve trusted boundaries only; caller paths must still reject every symlink.
    user_home, state_home = Path.home().resolve(), home().resolve()
    if not root.is_dir() or root == Path(root.anchor) or root in (user_home, state_home):
        raise OnboardingProblem("project_required", "Choose the specific existing project folder, not your home or filesystem root.")
    if user_home.is_relative_to(root) or state_home.is_relative_to(root) or root.is_relative_to(state_home):
        raise OnboardingProblem("unsafe_project", "Project scope must not include Theo's private account state.")
    return root


def private_directory(path: Path) -> Path:
    path = no_symlinks(path.absolute())
    with parent_descriptor(path / ".guard", create=True):
        info = path.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OnboardingProblem("unsafe_state", "Theo needs a private, user-owned state directory; existing permissions were not changed.")
    return path


def _key(root: Path, host: str) -> str:
    return hashlib.sha256(f"{root}\0{host}".encode()).hexdigest()


def record_path(root: Path, host: str) -> Path:
    return home() / "projects" / f"{_key(root, host)}.json"


def read_record(root: Path, host: str) -> dict[str, Any] | None:
    path = record_path(root, host)
    content = read_bytes(path)
    if content is None:
        return None
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise OnboardingProblem("unsafe_state", "Theo's setup receipt is not private; it was not used.")
    try:
        record = json.loads(content)
    except ValueError as exc:
        raise OnboardingProblem("invalid_state", "Theo's setup receipt is invalid; run doctor before recovering it.") from exc
    if (not isinstance(record, dict) or record.get("format") != STATE_FORMAT
            or record.get("project") != str(root) or record.get("host") != host):
        raise OnboardingProblem("invalid_state", "Theo's setup receipt does not belong to this project and host.")
    return record


def write_record(root: Path, host: str, record: dict[str, Any]) -> None:
    private_directory(home())
    private_directory(record_path(root, host).parent)
    value = {**record, "format": STATE_FORMAT, "project": str(root), "host": host}
    atomic_write(record_path(root, host), (json.dumps(value, sort_keys=True) + "\n").encode())


@contextmanager
def project_lock(root: Path, host: str) -> Iterator[None]:
    folder = private_directory(home() / "locks")
    path = folder / f"{_key(root, host)}.lock"
    with parent_descriptor(path) as parent:
        descriptor = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=parent)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OnboardingProblem("unsafe_state", "Theo's setup lock is not a private regular file.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise OnboardingProblem("setup_running", "Another Theo setup is running for this project. Let it finish, then rerun.") from exc
        yield
    finally:
        os.close(descriptor)


def changed_paths(root: Path, values: Any) -> list[Path]:
    if not isinstance(values, list) or len(values) > 32 or any(not isinstance(item, str) for item in values):
        raise OnboardingProblem("connector_contract", "The installed connector returned an unsupported change list.")
    paths = [no_symlinks(root / item) for item in values]
    if any(not path.is_relative_to(root) or path == root or ".git" in path.relative_to(root).parts
           for path in paths) or len(set(paths)) != len(paths):
        raise OnboardingProblem("connector_scope", "The connector requested a path outside the project configuration scope.")
    return paths


def snapshots(root: Path, host: str, paths: list[Path],
              previous: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep the first before-image across idempotent setup and mode switches."""
    result = {item["path"]: item for item in previous}
    backup_dir = private_directory(home() / "backups" / _key(root, host))
    for path in paths:
        relative = str(path.relative_to(root))
        if relative in result:
            continue
        before = read_bytes(path)
        backup = hashlib.sha256(relative.encode()).hexdigest() + "-" + secrets.token_hex(8)
        if before is not None:
            destination = backup_dir / backup
            atomic_write(destination, before, check_expected=True)
        result[relative] = {
            "path": relative, "backup": backup if before is not None else None,
            "before_sha256": hashlib.sha256(before).hexdigest() if before is not None else None,
            "mode": stat.S_IMODE(path.stat().st_mode) if before is not None else None,
            "after_sha256": None,
        }
    return list(result.values())


def seal_snapshots(root: Path, values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sealed = []
    for item in values:
        path = changed_paths(root, [item["path"]])[0]
        after = read_bytes(path)
        if after is None:
            raise OnboardingProblem("setup_interrupted", "A managed file is missing after configuration; run doctor and rerun setup.")
        sealed.append({**item, "after_mode": stat.S_IMODE(path.stat().st_mode),
                       "after_sha256": hashlib.sha256(after).hexdigest()
                       if item.get("recoverable", True) else None})
    return sealed


def restore(root: Path, host: str, record: dict[str, Any]) -> int:
    """Preflight all files; never clobber edits made after Theo configured the project."""
    values = record.get("snapshots", [])
    if not isinstance(values, list) or len(values) > 32:
        raise OnboardingProblem("invalid_state", "The recovery receipt is invalid.")
    planned = []
    for item in values:
        if not isinstance(item, dict):
            raise OnboardingProblem("invalid_state", "The recovery receipt is invalid.")
        path = changed_paths(root, [item.get("path")])[0]
        current = read_bytes(path)
        digest = hashlib.sha256(current).hexdigest() if current is not None else None
        if (not item.get("after_sha256") or digest != item["after_sha256"]
                or stat.S_IMODE(path.stat().st_mode) != item.get("after_mode")):
            raise OnboardingProblem("files_changed", "Project configuration changed after Theo setup. Nothing was restored; preserve those edits and inspect the private backup.")
        before = None
        if item.get("backup") is not None:
            expected_prefix = hashlib.sha256(str(path.relative_to(root)).encode()).hexdigest() + "-"
            backup_name = item["backup"]
            if (not isinstance(backup_name, str) or not backup_name.startswith(expected_prefix)
                    or len(backup_name) != len(expected_prefix) + 16
                    or any(character not in "0123456789abcdef" for character in backup_name[len(expected_prefix):])):
                raise OnboardingProblem("invalid_state", "The recovery backup does not match this path.")
            before = read_bytes(home() / "backups" / _key(root, host) / backup_name)
            if before is None or hashlib.sha256(before).hexdigest() != item.get("before_sha256"):
                raise OnboardingProblem("invalid_state", "The private recovery backup did not pass its integrity check.")
        mode = item.get("mode")
        if before is not None and (not isinstance(mode, int) or mode & ~0o777):
            raise OnboardingProblem("invalid_state", "The recovery file mode is invalid.")
        planned.append((path, current, before, mode))
    for path, current, before, mode in planned:
        if before is None:
            with parent_descriptor(path) as parent:
                if read_bytes(path) != current:
                    raise OnboardingProblem("files_changed", "Configuration changed during recovery; remaining files were left unchanged.")
                os.unlink(path.name, dir_fd=parent)
        else:
            assert isinstance(mode, int)  # All restore modes were checked before the first write.
            atomic_write(path, before, mode=mode, expected=current, check_expected=True)
    write_record(root, host, {**record, "stage": "disconnected", "snapshots": [], "host_verified": False})
    return len(planned)
