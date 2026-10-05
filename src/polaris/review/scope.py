"""Bounded source discovery. File bytes are read through no-follow directory descriptors."""

from __future__ import annotations

import errno
import fnmatch
import os
import stat
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from polaris.review.analyzers.base import GENERATED_PARTS, generated_reason, language_for_path
from polaris.review.models import (
    PRUNED_DIRECTORIES,
    SourceFile,
    WorkflowReviewConfig,
    valid_source_path,
)

SCOPE_LIMIT_PATH = "__polaris_unreviewed_scope__"
OVERSIZED_SAMPLE_BYTES = 65_536
# Dependency, build-output and cache folders. A Git project's ignore rules normally leave these
# out; a plain folder has none, so a folder check skips them by name. What they hold is installed,
# generated or vendored (the engine treats generated and vendored files as not applicable too).
FOLDER_SKIPPED = PRUNED_DIRECTORIES | GENERATED_PARTS | frozenset({
    "out", ".nuxt", ".output", ".svelte-kit", ".turbo", ".vercel", ".netlify", ".cache",
    ".parcel-cache", ".vite", ".expo", ".angular", ".docusaurus", ".serverless", ".terraform",
    ".gradle", ".dart_tool", "bower_components", "jspm_packages", "target", "Pods", ".yarn",
    ".pnpm-store", "storybook-static", ".wrangler", ".nyc_output", "htmlcov",
})
# Version-control folders are skipped too, but they aren't worth naming to the user.
VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn"})


@dataclass(frozen=True)
class FolderListing:
    """A plain folder's files (relative POSIX paths, sorted), the dependency and build folders that
    were skipped (relative paths, bounded), and why the walk stopped early (None: it saw everything)."""

    files: tuple[str, ...]
    skipped: tuple[str, ...] = ()
    truncated: str | None = None


def folder_files(root: Path, *, max_files: int, max_entries: int | None = None,
                 max_skipped: int = 200) -> FolderListing:
    """List a folder that isn't a Git project: bounded, deterministic, never following a link.

    It plays the part `git ls-files` plays for a Git project. Every entry that isn't a directory
    is listed, links and special files included, so the collector can say why it didn't read
    them. Folders named in `FOLDER_SKIPPED` are recorded and never entered; a folder that can't
    be opened, or whose name isn't a valid source path, is listed as itself for the same reason.
    Raises OSError when the folder itself can't be read.
    """
    if max_files < 1 or max_skipped < 0:
        raise ValueError("folder listing bounds must be positive")
    budget = max_entries if max_entries is not None else max_files * 4 + 32
    files: list[str] = []
    skipped: list[str] = []
    truncated: str | None = None
    pending = [""]  # a stack of folders still to read; children go on in reverse sorted order
    while pending and truncated is None:
        relative = pending.pop()
        parts = tuple(relative.split("/")) if relative else ()
        try:
            descriptor = _open_directory(root, parts)
        except OSError:
            if not relative:
                raise
            files.append(relative)  # the collector reports it as unreadable
            continue
        entries: list[tuple[str, bool]] = []
        try:
            with os.scandir(descriptor) as iterator:
                for entry in iterator:
                    if budget <= 0:
                        truncated = "directory_entry_limit"
                        break
                    budget -= 1
                    try:
                        directory = entry.is_dir(follow_symlinks=False)
                    except OSError:
                        directory = False
                    entries.append((entry.name, directory))
        finally:
            os.close(descriptor)
        children: list[str] = []
        for name, directory in sorted(entries):
            path = f"{relative}/{name}" if relative else name
            if directory and (name in FOLDER_SKIPPED or name.endswith(".egg-info")):
                if len(skipped) < max_skipped:
                    skipped.append(path)
            elif directory and valid_source_path(path):
                children.append(path)
            elif len(files) >= max_files:
                truncated = truncated or "file_limit"
                break
            else:
                files.append(path)
        pending.extend(reversed(children))
    return FolderListing(tuple(sorted(files)), tuple(skipped), truncated)


def matches(path: str, patterns: Iterable[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(path, pattern)
        or (pattern.startswith("**/") and fnmatch.fnmatchcase(path, pattern[3:]))
        for pattern in patterns
    )


def _directory_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise OSError("safe directory descriptors unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_directory(root: Path, parts: tuple[str, ...]) -> int:
    descriptor = os.open(root, _directory_flags())
    try:
        for part in parts:
            child = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def read_scoped_text(
    root: Path, relative: str, limit: int, *, prefix: bool = False,
) -> tuple[str | None, str | None]:
    """Preserve exact UTF-8 bytes/newlines; never follow a symlink in any source path component.

    With `prefix`, a larger file yields its first `limit` bytes (a sample for classification,
    never analyzed as the file's content).
    """
    if not valid_source_path(relative):
        return None, "invalid_path"
    if isinstance(limit, bool) or limit < 1:
        return None, "file_too_large"
    directory: int | None = None
    descriptor: int | None = None
    try:
        parts = tuple(relative.split("/"))
        directory = _open_directory(root, parts[:-1])
        metadata = os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
        if stat.S_ISLNK(metadata.st_mode):
            return None, "symlink"
        if not stat.S_ISREG(metadata.st_mode):
            return None, "not_regular_file"
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory,
        )
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            return None, "not_regular_file"
        if metadata.st_size > limit and not prefix:
            return None, "file_too_large"
        content = bytearray()
        while len(content) <= limit:
            block = os.read(descriptor, min(65_536, limit + 1 - len(content)))
            if not block:
                break
            content.extend(block)
        if len(content) > limit:
            if not prefix:
                return None, "file_too_large"
            del content[limit:]
        if b"\0" in content:
            return None, "binary"
        try:
            return bytes(content).decode("utf-8", "ignore" if prefix else "strict"), None
        except UnicodeError:
            return None, "invalid_encoding"
    except OSError as exc:
        return None, "unsafe_path" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "unreadable"
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if directory is not None:
            os.close(directory)


def oversized_reason(root: Path, relative: str) -> str:
    """Why a source file over the size limit is skipped. Generated or minified data (by name, or
    by a bounded sample of its first bytes) is not source code; anything else stays visible,
    unreviewed scope."""
    reason = generated_reason(relative, None)
    if reason is None:
        sample, _ = read_scoped_text(root, relative, OVERSIZED_SAMPLE_BYTES, prefix=True)
        reason = generated_reason(relative, sample) if sample else None
    return reason or "file_too_large"


def workflow_sources_from_paths(
    paths: Iterable[Path], *, root: Path, config: WorkflowReviewConfig | None = None,
) -> list[SourceFile]:
    """All encountered file types stay visible, even unsupported/excluded/oversized inputs.

    Named dependency/cache/VCS directories are represented by explicit advisory prune
    records, never descended. This collector does not execute Git or repository ignore
    helpers; caller-configured include/exclude patterns define additional selection.
    The limit sentinel explicitly records any remaining scope without enumerating it.
    """
    settings = config or WorkflowReviewConfig()
    original_root = root.absolute()
    root = root.resolve()
    sources: list[SourceFile] = []
    seen: set[str] = set()
    total_bytes = 0
    remaining_entries = settings.max_files * 4 + 32
    truncated: str | None = None

    def add(source: SourceFile) -> bool:
        nonlocal truncated
        if source.path in seen:
            return True
        if len(sources) >= settings.max_files:
            truncated = truncated or "file_limit"
            return False
        seen.add(source.path)
        sources.append(source)
        return True

    def visit(relative: str) -> None:
        nonlocal total_bytes, remaining_entries, truncated
        if truncated:
            return
        if relative and not valid_source_path(relative):
            add(SourceFile(relative, None, skip="invalid_path"))
            return
        parts = tuple(relative.split("/")) if relative else ()
        descriptor: int | None = None
        try:
            parent = _open_directory(root, parts[:-1]) if parts else None
            try:
                metadata = os.stat(parts[-1], dir_fd=parent, follow_symlinks=False) if parts else root.stat()
            finally:
                if parent is not None:
                    os.close(parent)
            if stat.S_ISLNK(metadata.st_mode):
                add(SourceFile(relative, None, skip="symlink"))
                return
            if stat.S_ISDIR(metadata.st_mode):
                if parts and (parts[-1] in PRUNED_DIRECTORIES or parts[-1].endswith(".egg-info")):
                    add(SourceFile(relative, None, skip="pruned_directory"))
                    return
                descriptor = _open_directory(root, parts)
                names: list[str] = []
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        if remaining_entries <= 0:
                            truncated = "directory_entry_limit"
                            break
                        remaining_entries -= 1
                        names.append(entry.name)
                # This directory's names are bounded too: no unbounded listdir/sort of
                # attacker-created entries before applying the source-count limit.
                for name in sorted(names):
                    if truncated:
                        break
                    visit(f"{relative}/{name}" if relative else name)
                return
            if not stat.S_ISREG(metadata.st_mode):
                add(SourceFile(relative, None, skip="not_regular_file"))
                return
        except OSError as exc:
            add(SourceFile(relative or SCOPE_LIMIT_PATH, None,
                           skip="unsafe_path" if exc.errno in (errno.ELOOP, errno.ENOTDIR) else "unreadable"))
            return
        finally:
            if descriptor is not None:
                os.close(descriptor)
        if len(sources) >= settings.max_files:
            truncated = "file_limit"
            return
        if not matches(relative, settings.include) or matches(relative, settings.exclusions):
            add(SourceFile(relative, None, skip="excluded"))
        elif language_for_path(relative) == "unsupported":
            # Unsupported file bodies (including .env) are not read just to ignore them.
            add(SourceFile(relative, None, skip="unsupported_language"))
        elif total_bytes >= settings.max_total_bytes:
            add(SourceFile(relative, None, skip="total_source_limit"))
        else:
            limit = min(settings.max_file_bytes, settings.max_total_bytes - total_bytes)
            text, reason = read_scoped_text(root, relative, limit)
            if text is not None:
                total_bytes += len(text.encode("utf-8"))
            elif reason == "file_too_large":
                reason = "total_source_limit" if limit < settings.max_file_bytes else oversized_reason(root, relative)
            add(SourceFile(relative, text, skip=reason))

    for index, path in enumerate(paths):
        if index >= settings.max_files:
            truncated = "path_argument_limit"
        if truncated:
            break
        if path.is_absolute():
            try:
                relative = path.relative_to(original_root).as_posix()
            except ValueError:
                try:
                    relative = path.relative_to(root).as_posix()
                except ValueError:
                    add(SourceFile(path.name or SCOPE_LIMIT_PATH, None, skip="outside_root"))
                    continue
        else:
            relative = path.as_posix()
        visit("" if relative == "." else relative)
    if truncated:
        sources.append(SourceFile(SCOPE_LIMIT_PATH, None, skip=truncated))
    return sources
