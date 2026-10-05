"""POSIX no-follow workspace access.

Directory descriptors prevent following swapped symlinks. Namespace/content rechecks detect
ordinary races but cannot implement a filesystem-wide compare-and-swap against an adversary.
The optional local apply operation is for a caller-controlled, quiescent worktree.
"""

from __future__ import annotations

import errno
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from polaris.engineering.errors import EngineeringError
from polaris.engineering.models import FileState
from polaris.engineering.security import relative_path
from polaris.jsonio import digest_bytes, digest_json


def _identity(info: os.stat_result) -> tuple[int, int]:
    return info.st_dev, info.st_ino


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
        info.st_mode,
        info.st_nlink,
    )


def _directory_flags() -> int:
    if (
        os.name != "posix"
        or not hasattr(os, "O_NOFOLLOW")
        or not hasattr(os, "O_DIRECTORY")
        or os.open not in os.supports_dir_fd
        or os.stat not in os.supports_dir_fd
    ):
        raise EngineeringError("unsupported_platform")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _read_error(exc: OSError) -> EngineeringError:
    return EngineeringError(
        "unsafe_file" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "unreadable_source"
    )


def _open_root(root: Path) -> int:
    flags = _directory_flags()
    if not root.is_absolute() or ".." in root.parts:
        raise EngineeringError("invalid_path")
    descriptor = os.open("/", flags)
    try:
        for part in root.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise _read_error(exc) from None


@dataclass(frozen=True)
class ReadSource:
    state: FileState
    text: str
    fingerprint: tuple[int, ...]


class Workspace:
    def __init__(self, root: Path, *, max_file_bytes: int) -> None:
        self.root = root.absolute()
        self.max_file_bytes = max_file_bytes
        self.fd = _open_root(self.root)
        self.identity = _identity(os.fstat(self.fd))
        self.root_digest = digest_json(
            {"root": self.root.as_posix(), "device": self.identity[0], "inode": self.identity[1]}
        )

    def __enter__(self) -> Workspace:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        os.close(self.fd)

    def assert_root(self) -> None:
        descriptor = _open_root(self.root)
        try:
            if _identity(os.fstat(descriptor)) != self.identity:
                raise EngineeringError("race_detected")
        finally:
            os.close(descriptor)

    def directory(self, relative: str = ".") -> int:
        relative_path(relative, allow_root=True)
        descriptor = os.dup(self.fd)
        try:
            if relative != ".":
                for part in relative.split("/"):
                    next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
                    os.close(descriptor)
                    descriptor = next_descriptor
            return descriptor
        except OSError as exc:
            os.close(descriptor)
            raise _read_error(exc) from None

    def parent(self, relative: str) -> tuple[int, str]:
        relative_path(relative)
        parent, separator, name = relative.rpartition("/")
        return self.directory(parent if separator else "."), name if separator else relative

    def assert_parent(self, relative: str, descriptor: int) -> None:
        self.assert_root()
        current, _ = self.parent(relative)
        try:
            if _identity(os.fstat(current)) != _identity(os.fstat(descriptor)):
                raise EngineeringError("race_detected")
        finally:
            os.close(current)

    def probe(self, relative: str, *, allow_missing: bool = False) -> None:
        """Check a path without reading content; used only for action-scope assessment."""
        descriptor, name = self.parent(relative)
        try:
            try:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if allow_missing:
                    return
                raise
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise EngineeringError("unsafe_file")
        except OSError as exc:
            raise _read_error(exc) from None
        finally:
            os.close(descriptor)

    def read(self, relative: str) -> ReadSource:
        descriptor, name = self.parent(relative)
        file_descriptor: int | None = None
        try:
            file_descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor
            )
            before = os.fstat(file_descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) > 0o777
            ):
                raise EngineeringError("unsafe_file")
            if before.st_size > self.max_file_bytes:
                raise EngineeringError("source_limit")
            chunks: list[bytes] = []
            size = 0
            while True:
                chunk = os.read(file_descriptor, min(65_536, self.max_file_bytes + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > self.max_file_bytes:
                    raise EngineeringError("source_limit")
            after = os.fstat(file_descriptor)
            current = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if _fingerprint(before) != _fingerprint(after) or _fingerprint(current) != _fingerprint(after):
                raise EngineeringError("race_detected")
            self.assert_parent(relative, descriptor)
            raw = b"".join(chunks)
            text = raw.decode("utf-8")
            if "\x00" in text:
                raise EngineeringError("unreadable_source")
            return ReadSource(
                state=FileState(
                    path=relative,
                    sha256=digest_bytes(raw),
                    size_bytes=len(raw),
                    mode=stat.S_IMODE(after.st_mode),
                ),
                text=text,
                fingerprint=_fingerprint(after),
            )
        except OSError as exc:
            raise _read_error(exc) from None
        except UnicodeError:
            raise EngineeringError("unreadable_source") from None
        finally:
            if file_descriptor is not None:
                os.close(file_descriptor)
            os.close(descriptor)
