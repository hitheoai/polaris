"""Read-only git helpers. Polaris never writes to, commits to, or pushes a repository."""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Any

from polaris.review.analyzers.base import generated_reason, language_for_path
from polaris.review.analyzers.process import run_bounded
from polaris.review.engine import read_text
from polaris.review.extract import parse_unified_diff
from polaris.review.models import (
    PRUNED_DIRECTORIES,
    SourceFile,
    WorkflowReviewConfig,
    valid_source_path,
)
from polaris.review.scope import SCOPE_LIMIT_PATH, matches, oversized_reason, read_scoped_text

GIT_ENV = {
    "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin",
    "HOME": os.devnull, "GIT_OPTIONAL_LOCKS": "0", "GIT_TERMINAL_PROMPT": "0",
    "GIT_PAGER": "cat", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_ATTR_NOSYSTEM": "1",
    "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1", "LC_ALL": "C",
}
_SAFE_CONFIG = (
    "core.fsmonitor=false", f"core.hooksPath={os.devnull}", f"core.attributesFile={os.devnull}",
    "core.pager=cat", "diff.external=", "credential.helper=", "protocol.allow=never",
)
_OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")


class GitError(RuntimeError):
    pass


# Filter-driver overrides are recomputed for every Git call, except within one source
# collection (see filter_scope), so a long-lived server never reuses stale configuration.
_FILTER_SCOPE: ContextVar[dict[str, tuple[str, ...]] | None] = ContextVar("polaris_git_filters", default=None)


@contextmanager
def filter_scope() -> Iterator[None]:
    if _FILTER_SCOPE.get() is not None:  # nested: keep the enclosing review's scope
        yield
        return
    token = _FILTER_SCOPE.set({})
    try:
        yield
    finally:
        _FILTER_SCOPE.reset(token)


def _filter_overrides(executable: str, root: Path, prefix: list[str], timeout: float) -> tuple[str, ...]:
    # Even --no-textconv does not disable clean/process filters used by worktree diffs.
    # Read only their names, not values (which can contain secrets), then override all
    # configured drivers. Git's config builtin does not execute them.
    scope = _FILTER_SCOPE.get()
    if scope is not None and str(root) in scope:
        return scope[str(root)]
    filters = run_bounded(
        [*prefix, "config", "--name-only", "--get-regexp", r"^filter\..*\.(clean|smudge|process|required)$"],
        cwd=root, env=GIT_ENV, timeout=min(timeout, 10), max_output_bytes=65_536,
    )
    if filters.status != "ok" or filters.returncode not in (0, 1):
        raise GitError("git_config_unavailable")
    try:
        names = filters.stdout.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise GitError("git_invalid_encoding") from exc
    drivers: set[str] = set()
    for name in names:
        if not re.fullmatch(r"filter\.[^=\x00-\x1f]+\.(clean|smudge|process|required)", name):
            raise GitError("git_filter_configuration_invalid")
        drivers.add(name.rsplit(".", 1)[0])
    if len(drivers) > 64:
        raise GitError("git_filter_configuration_limit")
    overrides: list[str] = []
    for driver in sorted(drivers):
        for kind, value in (("clean", ""), ("smudge", ""), ("process", ""), ("required", "false")):
            overrides.extend(("-c", f"{driver}.{kind}={value}"))
    if scope is not None:
        scope[str(root)] = tuple(overrides)
    return tuple(overrides)


def git_raw(root: Path, *args: str, timeout: float = 60, max_output_bytes: int = 8_000_000,
            stdin: bytes | None = None) -> bytes:
    executable = shutil.which("git", path=GIT_ENV["PATH"])
    if executable is None:
        raise GitError("git_unavailable")
    root = root.resolve()
    prefix = [executable, "--no-pager", "-C", str(root)]
    for setting in _SAFE_CONFIG:
        prefix.extend(("-c", setting))
    prefix.extend(_filter_overrides(executable, root, prefix, timeout))
    if args and args[0] in ("diff", "ls-files"):
        # A malicious core.worktree must not redirect source reads outside caller scope.
        prefix.extend(("--work-tree", str(root)))
    done = run_bounded(
        [*prefix, *args], cwd=root, env=GIT_ENV, timeout=timeout,
        max_output_bytes=max_output_bytes, stdin=stdin,
    )
    if done.status != "ok":
        raise GitError("git_" + done.status)
    if done.returncode != 0:
        raise GitError("git_failed")
    return done.stdout


def git(root: Path, *args: str, timeout: float = 60, max_output_bytes: int = 8_000_000) -> str:
    try:
        return git_raw(root, *args, timeout=timeout, max_output_bytes=max_output_bytes).decode("utf-8")
    except UnicodeError as exc:
        raise GitError("git_invalid_encoding") from exc


def repo_root(path: Path) -> Path | None:
    try:
        return Path(git(path, "rev-parse", "--show-toplevel").strip()).resolve()
    except GitError:
        return None


def show(root: Path, revision: str, path: str) -> str | None:
    """File contents at a revision ('' + ':' = the index), or None if it didn't exist."""
    if revision.startswith("-") or not valid_source_path(path):
        return None
    try:
        return git(root, "show", f"{revision}:{path}")
    except GitError:
        return None


def has_head(root: Path) -> bool:
    try:
        git(root, "rev-parse", "--verify", "--quiet", "HEAD")
        return True
    except GitError:
        return False


def diff_text(root: Path, *, staged: bool = False, revision_range: str | None = None) -> str:
    args = ["diff", "--no-color", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all", "--unified=0", "-M"]
    if revision_range:
        if revision_range.startswith("-"):
            raise GitError("invalid revision range")
        args.append(revision_range)
    elif staged:
        args.append("--cached")
    elif has_head(root):
        args.append("HEAD")
    return git(root, *args, "--", "*.py")


def sources_from_git(root: Path, *, staged: bool = False, revision_range: str | None = None,
                     include_untracked: bool = True, max_bytes: int = 2_000_000) -> list[SourceFile]:
    """Changed Python files with their previous versions, ready for `Reviewer.review_sources`."""
    base, target = ("HEAD", None)
    if revision_range:
        left, _, right = revision_range.partition("..")
        base, target = (left.rstrip(".") or "HEAD"), (right.lstrip(".") or "HEAD")
    elif staged:
        target = ""  # the index
    head = has_head(root)
    sources: list[SourceFile] = []
    for item in parse_unified_diff(diff_text(root, staged=staged, revision_range=revision_range)):
        if item.new_path is None:
            continue
        if target is None:
            after = read_text(root, item.new_path, max_bytes)
        else:
            after = show(root, target, item.new_path)
        before = show(root, base, item.old_path) if (item.old_path and (head or revision_range)) else None
        if after is None:
            sources.append(SourceFile(item.new_path, None, skip="unreadable"))
        else:
            sources.append(SourceFile(item.new_path, after, before, frozenset(item.changed_lines)))
    if include_untracked and not staged and not revision_range:
        listed = git(root, "ls-files", "--others", "--exclude-standard", "--", "*.py")
        for name in listed.splitlines():
            text = read_text(root, name, max_bytes)
            sources.append(SourceFile(name, text) if text is not None else SourceFile(name, None, skip="unreadable"))
    return sources


def _resolve_revision(root: Path, revision: str) -> str:
    if not revision or revision.startswith("-") or "\0" in revision or len(revision) > 1024:
        raise GitError("invalid_revision")
    value = git(root, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}").strip()
    if not _OID.fullmatch(value):
        raise GitError("invalid_revision")
    return value


def _workflow_revisions(
    root: Path, staged: bool, revision_range: str | None,
) -> tuple[str | None, str | None, list[str]]:
    head = _resolve_revision(root, "HEAD") if has_head(root) else None
    if revision_range:
        if "..." in revision_range:
            left, right = revision_range.split("...", 1)
            base = _resolve_revision(root, left or "HEAD")
            target = _resolve_revision(root, right or "HEAD")
            base = git(root, "merge-base", base, target).strip()
            if not _OID.fullmatch(base):
                raise GitError("invalid_merge_base")
        else:
            left, separator, right = revision_range.partition("..")
            base = _resolve_revision(root, left or "HEAD")
            target = _resolve_revision(root, (right or "HEAD") if separator else "HEAD")
        return base, target, [base, target]
    if staged:
        return head, "", ["--cached", *([head] if head else [])]
    return head, None, [head] if head else []


def _changed_paths(text: str) -> list[tuple[str, str | None, str]]:
    fields = text.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    index = 0
    paths: list[tuple[str, str | None, str]] = []
    while index < len(fields):
        status = fields[index]
        index += 1
        if not re.fullmatch(r"(?:[AMDUT]|[RC][0-9]{1,3})", status):
            raise GitError("invalid_git_name_status")
        count = 2 if status[0] in "RC" else 1
        if index + count > len(fields):
            raise GitError("invalid_git_name_status")
        previous = fields[index] if count == 2 else None
        path = fields[index + count - 1]
        index += count
        paths.append((path, previous, status[0]))
    return paths


def _revision_source(
    root: Path, revision: str, path: str, limit: int,
) -> tuple[str | None, str | None]:
    """Read a regular blob only, without filters, symlinks, textconv, or unbounded output."""
    if not valid_source_path(path):
        return None, "invalid_path"
    if revision == "":
        record = git(root, "ls-files", "--stage", "-z", "--", path)
    else:
        record = git(root, "ls-tree", "-z", revision, "--", path)
    rows = [row for row in record.split("\0") if row]
    if not rows:
        return None, None
    if len(rows) != 1 or "\t" not in rows[0]:
        return None, "unmerged_or_ambiguous"
    header, actual_path = rows[0].split("\t", 1)
    values = header.split(" ")
    if len(values) != 3 or actual_path != path:
        return None, "invalid_blob_entry"
    mode, middle, last = values
    if mode not in ("100644", "100755"):
        return None, "symlink" if mode == "120000" else "not_regular_file"
    if revision == "":
        oid = middle
        if last != "0":
            return None, "unmerged"
    else:
        oid = last
        if middle != "blob":
            return None, "not_regular_file"
    if not _OID.fullmatch(oid):
        return None, "invalid_blob_entry"
    size = git(root, "cat-file", "-s", oid, max_output_bytes=1_024).strip()
    if not size.isdigit():
        return None, "invalid_blob_size"
    if int(size) > limit:
        return None, "file_too_large"
    content = git(root, "cat-file", "blob", oid, max_output_bytes=max(1, limit + 1))
    if "\0" in content:
        return None, "binary"
    return content, None


def revision_blobs(
    root: Path, revision: str, paths: list[str], limit: int,
) -> dict[str, tuple[str | None, str | None]]:
    """(content, skip) of many paths at one commit: one tree listing plus batched blob reads.

    Same rules as one-at-a-time reads (regular blobs only, no filters/textconv, bounded size),
    with a fixed number of Git processes instead of several per file.
    """
    results: dict[str, tuple[str | None, str | None]] = {}
    rows: dict[str, list[list[str]]] = {}
    for start in range(0, len(paths), 200):
        literal = [f":(literal){path}" for path in paths[start:start + 200]]
        listing = git(root, "ls-tree", "-r", "-l", "-z", "--full-tree", revision, "--", *literal,
                      max_output_bytes=16_000_000)
        for record in listing.split("\0"):
            if "\t" in record:
                header, name = record.split("\t", 1)
                rows.setdefault(name, []).append(header.split())
    wanted: list[tuple[str, str, int]] = []
    for path in paths:
        entries = rows.get(path)
        if not entries:
            results[path] = (None, None)
        elif len(entries) != 1 or len(entries[0]) != 4:
            results[path] = (None, "unmerged_or_ambiguous")
        elif entries[0][0] not in ("100644", "100755"):
            results[path] = (None, "symlink" if entries[0][0] == "120000" else "not_regular_file")
        elif entries[0][1] != "blob" or not _OID.fullmatch(entries[0][2]) or not entries[0][3].isdigit():
            results[path] = (None, "invalid_blob_entry")
        elif int(entries[0][3]) > limit:
            results[path] = (None, "file_too_large")
        else:
            wanted.append((path, entries[0][2], int(entries[0][3])))
    batch: list[tuple[str, str, int]] = []
    for item in [*wanted, None]:
        if item is not None and len(batch) < 1_000 and sum(size for *_, size in batch) + item[2] <= 64_000_000:
            batch.append(item)
            continue
        if batch:
            results.update(_read_batch(root, batch))
        batch = [item] if item is not None else []
    return results


def _read_batch(root: Path, batch: list[tuple[str, str, int]]) -> dict[str, tuple[str | None, str | None]]:
    total = sum(size for *_, size in batch) + 128 * len(batch)
    data = git_raw(root, "cat-file", "--batch", stdin="".join(f"{oid}\n" for _, oid, _ in batch).encode(),
                   max_output_bytes=total + 1)
    results: dict[str, tuple[str | None, str | None]] = {}
    offset = 0
    for path, oid, size in batch:
        end = data.find(b"\n", offset)
        header = data[offset:end].decode("ascii", "replace").split() if end >= 0 else []
        if len(header) != 3 or header[0] != oid or header[1] != "blob" or header[2] != str(size):
            raise GitError("invalid_batch_output")
        content = data[end + 1:end + 1 + size]
        offset = end + 1 + size + 1
        if b"\0" in content:
            results[path] = (None, "binary")
            continue
        try:
            results[path] = (content.decode("utf-8"), None)
        except UnicodeError:
            results[path] = (None, "invalid_encoding")
    return results


def revision_identity(root: Path, revision_range: str) -> tuple[str | None, str | None]:
    """The (base, target) commits a range resolves to; commits themselves never change."""
    base, target, _ = _workflow_revisions(root.resolve(), False, revision_range)
    return base, target


_GIT_ESCAPES = {'"': 0x22, "\\": 0x5C, "a": 0x07, "b": 0x08, "t": 0x09, "n": 0x0A, "v": 0x0B, "f": 0x0C,
                "r": 0x0D}


def _unquoted_path(value: str) -> str | None:
    """Undo Git's C-style path quoting (octal UTF-8 bytes, \\t, \\" ...) left after diff parsing.

    Valid repository paths never contain a backslash, so one marks a quoted path.
    """
    if "\\" not in value:
        return value
    output = bytearray()
    index = 0
    while index < len(value):
        character = value[index]
        if character != "\\":
            output.extend(character.encode("utf-8"))
            index += 1
            continue
        octal = value[index + 1:index + 4]
        if len(octal) == 3 and all(digit in "01234567" for digit in octal):
            output.append(int(octal, 8) & 0xFF)
            index += 4
        elif value[index + 1:index + 2] in _GIT_ESCAPES:
            output.append(_GIT_ESCAPES[value[index + 1]])
            index += 2
        else:
            return None
    try:
        return output.decode("utf-8")
    except UnicodeError:
        return None


def changed_lines(
    root: Path, revision_range: str, *, max_output_bytes: int = 64_000_000,
) -> tuple[str, str, dict[str, frozenset[int]]]:
    """(base, target, {path: new-side line numbers}) changed by a revision range.

    Three-dot ranges compare against the merge base, like a pull request's diff. A zero-context
    diff lists added and modified lines (plus the line after a pure deletion). Renamed files keep
    their new path. Binary files and invalid paths are left out. Nothing is checked out or run.
    """
    root = root.resolve()
    with filter_scope():
        base, target, _ = _workflow_revisions(root, False, revision_range)
        if base is None or not target:
            raise GitError("invalid_revision_range")
        text = git(root, "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--ignore-submodules=all",
                   "--unified=0", "-M", base, target, "--", max_output_bytes=max_output_bytes)
    lines: dict[str, frozenset[int]] = {}
    for item in parse_unified_diff(text):
        path = _unquoted_path(item.new_path) if item.new_path is not None else None
        if path is None or item.binary or not valid_source_path(path):
            continue
        lines[path] = frozenset(item.changed_lines)
    return base, target, lines


def base_revision_files(
    root: Path, revision_range: str, limits: dict[str, int],
) -> tuple[str | None, dict[str, bytes | None]]:
    """(base commit, {path: content}) at the base of a range, read in one batch.

    Used so a change under review can't loosen its own settings or baseline in CI.
    """
    root = root.resolve()
    base, _, _ = _workflow_revisions(root, False, revision_range)
    if base is None:
        return None, {path: None for path in limits}
    blobs = revision_blobs(root, base, sorted(limits), max(limits.values()))
    contents: dict[str, bytes | None] = {}
    for path, limit in limits.items():
        content, skip = blobs.get(path, (None, None))
        if content is not None and len(content.encode("utf-8")) > limit:
            content, skip = None, "file_too_large"
        if content is None and skip is not None:
            raise GitError(f"base_settings_{skip}")
        contents[path] = content.encode("utf-8") if content is not None else None
    return base, contents


def base_revision_file(root: Path, revision_range: str, path: str, limit: int) -> tuple[str | None, bytes | None]:
    """(base commit, content) of `path` at the base of a range: the merge base for A...B.

    Used so a change under review can't loosen its own settings or baseline in CI.
    """
    root = root.resolve()
    base, _, _ = _workflow_revisions(root, False, revision_range)
    if base is None:
        return None, None
    content, skip = _revision_source(root, base, path, limit)
    if content is None and skip is not None:
        raise GitError(f"base_settings_{skip}")
    return base, content.encode("utf-8") if content is not None else None


def workflow_sources_from_git(
    root: Path, *, staged: bool = False, revision_range: str | None = None,
    include_untracked: bool = True, max_bytes: int | None = None,
    max_files: int | None = None, max_total_bytes: int | None = None,
    config: WorkflowReviewConfig | None = None,
) -> list[SourceFile]:
    """Language-neutral inventory of exact changed snapshots, including unsupported/deleted paths.

    Full supplied changed files are reviewed, not only changed lines. The previous path is
    retained for renames; three-dot ranges read the true merge-base as their before version.
    A sentinel records remaining scope at count/output limits; Git failures raise GitError.
    """
    with filter_scope():
        return _workflow_sources(root, staged=staged, revision_range=revision_range,
                                 include_untracked=include_untracked, max_bytes=max_bytes, max_files=max_files,
                                 max_total_bytes=max_total_bytes, config=config)


def _workflow_sources(
    root: Path, *, staged: bool, revision_range: str | None, include_untracked: bool, max_bytes: int | None,
    max_files: int | None, max_total_bytes: int | None, config: WorkflowReviewConfig | None,
) -> list[SourceFile]:
    values: dict[str, Any] = (config or WorkflowReviewConfig()).model_dump(mode="python")
    for key, value in (("max_file_bytes", max_bytes), ("max_files", max_files), ("max_total_bytes", max_total_bytes)):
        if value is not None:
            values[key] = value
    settings = WorkflowReviewConfig.model_validate(values)
    root = root.resolve()
    base, target, revisions = _workflow_revisions(root, staged, revision_range)
    options = ["diff", "--no-color", "--no-ext-diff", "--no-textconv",
               "--ignore-submodules=dirty", "--name-status", "-z", "-M"]
    changed = _changed_paths(git(root, *options, *revisions, "--"))
    if base is None and not staged and not revision_range:
        # In an unborn repo, staged new files otherwise disappear from index-vs-worktree diff.
        changed = [*_changed_paths(git(root, *options, "--cached", "--")), *changed]
    if include_untracked and not staged and not revision_range:
        untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z", "--")
        changed.extend((name, None, "A") for name in untracked.split("\0") if name)
    # Last index/worktree status wins for a repeated name; there is only one supplied after.
    by_path = {path: (previous, status) for path, previous, status in changed}
    # Commit contents are read in batches (a fixed number of Git processes per review).
    readable = [
        (path, previous, status) for path, (previous, status) in sorted(by_path.items())[:settings.max_files]
        if valid_source_path(path) and (previous is None or valid_source_path(previous))
        and not any(part in PRUNED_DIRECTORIES or part.endswith(".egg-info") for part in path.split("/")[:-1])
        and matches(path, settings.include) and not matches(path, settings.exclusions)
        and language_for_path(path) != "unsupported"
    ]
    after_blobs = revision_blobs(root, target, [path for path, _, status in readable if status not in ("D", "U")],
                                 settings.max_file_bytes) if target else {}
    before_blobs = revision_blobs(root, base, sorted({previous or path for path, previous, status in readable
                                                      if status != "A"}), settings.max_file_bytes) if base else {}

    def from_batch(blobs: dict[str, tuple[str | None, str | None]], path: str, limit: int) -> tuple[str | None, str | None]:
        content, skip = blobs.get(path, (None, None))
        if content is not None and len(content.encode("utf-8")) > limit:
            return None, "file_too_large"
        return content, skip

    sources: list[SourceFile] = []
    total_bytes = 0
    for index, (path, (previous, status)) in enumerate(sorted(by_path.items())):
        if index >= settings.max_files:
            sources.append(SourceFile(SCOPE_LIMIT_PATH, None, skip="file_limit"))
            break
        if not valid_source_path(path) or (previous is not None and not valid_source_path(previous)):
            sources.append(SourceFile(path, None, skip="invalid_path", previous_path=previous))
            continue
        if any(part in PRUNED_DIRECTORIES or part.endswith(".egg-info") for part in path.split("/")[:-1]):
            sources.append(SourceFile(path, None, skip="pruned_directory", previous_path=previous))
            continue
        if not matches(path, settings.include) or matches(path, settings.exclusions):
            sources.append(SourceFile(path, None, skip="excluded", previous_path=previous))
            continue
        if language_for_path(path) == "unsupported":
            sources.append(SourceFile(path, None, skip="deleted" if status == "D" else "unsupported_language",
                                      previous_path=previous))
            continue
        after = before = None
        skip = "deleted" if status == "D" else "unmerged" if status == "U" else None
        before_skip = None
        if skip is None:
            remaining = settings.max_total_bytes - total_bytes
            if remaining <= 0:
                skip = "total_source_limit"
            else:
                limit = min(settings.max_file_bytes, remaining)
                if target is None:
                    after, skip = read_scoped_text(root, path, limit)
                elif target:
                    after, skip = from_batch(after_blobs, path, limit)
                else:
                    after, skip = _revision_source(root, target, path, limit)  # the index
                if after is None and skip is None:
                    skip = "unreadable"
                if skip == "file_too_large" and limit < settings.max_file_bytes:
                    skip = "total_source_limit"
                elif skip == "file_too_large":
                    # Generated data is not source; revisions are classified by name only.
                    skip = oversized_reason(root, path) if target is None else (generated_reason(path, None) or skip)
                if after is not None:
                    total_bytes += len(after.encode("utf-8"))
        if base is not None and status != "A":
            remaining = settings.max_total_bytes - total_bytes
            if remaining <= 0:
                before_skip = "total_source_limit"
            else:
                limit = min(settings.max_file_bytes, remaining)
                before, before_skip = from_batch(before_blobs, previous or path, limit)
                if before_skip == "file_too_large" and limit < settings.max_file_bytes:
                    before_skip = "total_source_limit"
                if before is not None:
                    total_bytes += len(before.encode("utf-8"))
        sources.append(SourceFile(path, after, before, skip=skip, previous_path=previous, before_skip=before_skip))
    return sources
