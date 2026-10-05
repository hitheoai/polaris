"""tsconfig.json / jsconfig.json path aliases, read as data. Nothing is executed or installed.

Supports `compilerOptions.baseUrl`, `compilerOptions.paths` and relative `extends` (string
or list). Package-name `extends` (from node_modules) are ignored. All returned paths are
repository-relative POSIX paths; targets that leave the repository are dropped.
"""

from __future__ import annotations

import json
import posixpath
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

CONFIG_NAMES = ("tsconfig.json", "jsconfig.json")
MAX_CONFIG_BYTES = 512_000
MAX_EXTENDS_DEPTH = 4
TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def is_config(path: str) -> bool:
    return posixpath.basename(path) in CONFIG_NAMES


def parse_jsonc(text: str) -> Any | None:
    """JSON with // and /* */ comments and trailing commas (tsconfig syntax); None if invalid."""
    if len(text) > MAX_CONFIG_BYTES:
        return None
    out: list[str] = []
    index, size, in_string = 0, len(text), False
    while index < size:
        char = text[index]
        if in_string:
            out.append(char)
            if char == "\\" and index + 1 < size:
                out.append(text[index + 1])
                index += 2
                continue
            if char == '"':
                in_string = False
            index += 1
            continue
        if char == '"':
            in_string = True
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = size if end < 0 else end
            continue
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = size if end < 0 else end + 2
            continue
        out.append(char)
        index += 1
    try:
        return json.loads(TRAILING_COMMA.sub(r"\1", "".join(out)))
    except (ValueError, RecursionError):
        return None


def _inside(path: str) -> str | None:
    normalized = posixpath.normpath(path)
    if normalized.startswith("../") or normalized == ".." or normalized.startswith("/"):
        return None
    return "" if normalized == "." else normalized


@dataclass(frozen=True)
class AliasConfig:
    directory: str
    base_url: str | None
    paths: tuple[tuple[str, tuple[str, ...]], ...]

    def candidates(self, specifier: str) -> list[str]:
        """Repository-relative module bases for a non-relative specifier, best match first."""
        results: list[str] = []
        exact = [targets for pattern, targets in self.paths if "*" not in pattern and pattern == specifier]
        for targets in exact:
            results.extend(targets)
        wildcard = sorted(
            ((pattern, targets) for pattern, targets in self.paths if "*" in pattern),
            key=lambda item: -len(item[0].partition("*")[0]),
        )
        for pattern, targets in wildcard:
            prefix, _, suffix = pattern.partition("*")
            if not specifier.startswith(prefix) or not specifier.endswith(suffix):
                continue
            if len(specifier) < len(prefix) + len(suffix):
                continue
            middle = specifier[len(prefix):len(specifier) - len(suffix)]
            results.extend(target.replace("*", middle, 1) for target in targets)
        if self.base_url is not None and not specifier.startswith((".", "/")):
            joined = _inside(posixpath.join(self.base_url, specifier) if self.base_url else specifier)
            if joined is not None:
                results.append(joined)
        return list(dict.fromkeys(item for item in results if item))


def load_alias_config(path: str, read: Callable[[str], str | None], *, depth: int = 0) -> AliasConfig | None:
    """Parse one config (following relative `extends`) using `read` for repository files."""
    text = read(path)
    data = parse_jsonc(text) if text else None
    if not isinstance(data, dict):
        return None
    directory = posixpath.dirname(path)
    raw_options = data.get("compilerOptions")
    options: dict[str, Any] = raw_options if isinstance(raw_options, dict) else {}
    inherited: AliasConfig | None = None
    extends = data.get("extends")
    parents = [extends] if isinstance(extends, str) else extends if isinstance(extends, list) else []
    for item in parents:
        if not isinstance(item, str) or not item.startswith(".") or depth >= MAX_EXTENDS_DEPTH:
            continue
        target = _inside(posixpath.join(directory, item))
        if target is None:
            continue
        if not target.endswith(".json"):
            target += ".json"
        parent = load_alias_config(target, read, depth=depth + 1)
        if parent is not None:
            inherited = parent
    base_value = options.get("baseUrl")
    base_url = _inside(posixpath.join(directory, base_value)) if isinstance(base_value, str) else None
    if base_url is None and inherited is not None:
        base_url = inherited.base_url
    raw_paths = options.get("paths")
    if isinstance(raw_paths, dict):
        anchor = (
            _inside(posixpath.join(directory, base_value)) if isinstance(base_value, str) else directory
        ) or ""
        mapped: list[tuple[str, tuple[str, ...]]] = []
        for pattern, targets in list(raw_paths.items())[:256]:
            if not isinstance(pattern, str) or not isinstance(targets, list):
                continue
            resolved = []
            for target in targets[:16]:
                if isinstance(target, str):
                    value = _inside(posixpath.join(anchor, target) if anchor else target)
                    if value:
                        resolved.append(value)
            if resolved:
                mapped.append((pattern, tuple(resolved)))
        paths = tuple(mapped)
    else:
        paths = inherited.paths if inherited is not None else ()
    return AliasConfig(directory=directory, base_url=base_url, paths=paths)


def ancestors(path: str) -> Iterable[str]:
    """Directories containing `path`, nearest first, ending with the repository root ''."""
    current = posixpath.dirname(path)
    while True:
        yield current
        if not current:
            return
        current = posixpath.dirname(current)


def config_paths_for(path: str) -> list[str]:
    """Candidate config files that could govern `path`, nearest first."""
    return [posixpath.join(folder, name) if folder else name for folder in ancestors(path) for name in CONFIG_NAMES]


def extends_targets(path: str, text: str) -> list[str]:
    data = parse_jsonc(text)
    if not isinstance(data, dict):
        return []
    extends = data.get("extends")
    values = [extends] if isinstance(extends, str) else extends if isinstance(extends, list) else []
    results = []
    for item in values:
        if isinstance(item, str) and item.startswith("."):
            target = _inside(posixpath.join(posixpath.dirname(path), item))
            if target:
                results.append(target if target.endswith(".json") else target + ".json")
    return results
