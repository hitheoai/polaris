"""Read a folder into the `{path: text}` shape `build_graph` takes. Bounded, never follows links."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from pathlib import Path

from polaris.graph.jsimports import CONFIG_NAMES, SCRIPT_SUFFIXES
from polaris.graph.model import Incomplete, Limits
from polaris.review.scope import folder_files, read_scoped_text

LISTING_LIMIT = 1_000_000


@dataclass(frozen=True)
class LoadedSources:
    files: dict[str, str]
    # Source files that were found but not read (path -> reason): too large, binary, a symlink...
    skipped: dict[str, str]
    incomplete: tuple[Incomplete, ...] = field(default_factory=tuple)


def load_directory(root: Path, *, limits: Limits | None = None) -> LoadedSources:
    """Python and TypeScript/JavaScript sources (plus tsconfig/jsconfig files) below `root`.

    Dependency, build-output and cache folders are skipped by name, exactly as a folder review
    skips them. Anything that is source but cannot be read is listed in `skipped`, not dropped.
    """
    limits = limits or Limits()
    root = root.resolve()
    listing = folder_files(root, max_files=LISTING_LIMIT)
    files: dict[str, str] = {}
    skipped: dict[str, str] = {}
    incomplete: list[Incomplete] = []
    if listing.truncated:
        incomplete.append(Incomplete(listing.truncated, None, "folder listing stopped early"))
    total = 0
    for relative in listing.files:
        is_source = relative.endswith((".py", *SCRIPT_SUFFIXES))
        if not is_source and posixpath.basename(relative) not in CONFIG_NAMES:
            continue
        if total >= limits.max_total_bytes:
            if is_source:
                skipped[relative] = "total_bytes_limit"
            continue
        text, reason = read_scoped_text(root, relative, limits.max_file_bytes)
        if text is None:
            if is_source:
                skipped[relative] = reason or "unreadable"
            continue
        files[relative] = text
        total += len(text)
    return LoadedSources(files, skipped, tuple(incomplete))
