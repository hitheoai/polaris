"""Bounded, non-executing discovery of the files a change depends on and the files that use it.

Only non-ignored files inside the worktree are eligible, read without following symlinks.
TypeScript/JavaScript imports (relative and tsconfig/jsconfig aliases, two levels deep),
the governing tsconfig chain and bounded reverse importers are handed to the analyzers as
read-only *context*: flows through helpers and from callers are followed, but context files
are not themselves reviewed for findings. The response lists only paths and digests.
Retrieved code is context, never policy or authority.
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Iterable
from pathlib import Path

from polaris.integrations._safe import IntegrationProblem, read_bytes
from polaris.integrations.freshness import SnapshotLimits, git_bytes, git_result
from polaris.jsonio import digest_text
from polaris.review.js.tsconfig import (
    MAX_CONFIG_BYTES,
    AliasConfig,
    config_paths_for,
    extends_targets,
    load_alias_config,
)
from polaris.review.models import PRUNED_DIRECTORIES, SourceFile
from polaris.workflow.models import ContextSummary, RelatedFile, RelatedReason

JS_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
JS_SPECIFIER = re.compile(r"""(?:\bfrom\s*|\brequire\s*\(\s*|\bimport\s*\(?\s*)(['"])([^'"\n]{1,300})\1""")
PY_IMPORT = re.compile(r"(?m)^\s*(?:from|import)\s+([A-Za-z_.][A-Za-z0-9_.]*)")
TEST_FILE = re.compile(
    r"(^|/)(__tests__|__mocks__|tests?|e2e|cypress|playwright|fixtures?|stories)/"
    r"|\.(test|spec|stories|e2e)\.[A-Za-z]+$|(^|/)test_[^/]+\.py$|_test\.py$"
)
# Server-side helpers are where sinks live; UI components rarely are.
PRIORITY_PATH = re.compile(
    r"(?i)(^|/)(lib|server|api|db|database|actions?|services?|utils?|helpers?|auth|data|integrations?|"
    r"clients?|queries|repositories|models|middleware)(/|\.|$)"
)
MANIFESTS = ("package.json", "pyproject.toml")
MAX_SCANNED_SOURCES = 2_000
MAX_SCAN_CHARS = 400_000
MAX_IMPORTER_SOURCES = 64
MAX_IMPORTER_CANDIDATES = 400
MAX_UNTRACKED_SCAN = 500


def repository_files(root: Path) -> set[str] | None:
    """Non-ignored tracked and untracked files (no submodules), or None if Git can't list them."""
    limits = SnapshotLimits(max_git_output_bytes=64_000_000)
    try:
        staged = git_bytes(root, "ls-files", "--stage", "-z", limits=limits)
        untracked = git_bytes(root, "ls-files", "--others", "--exclude-standard", "-z", limits=limits)
    except IntegrationProblem:
        return None
    files = set()
    for entry in staged.split(b"\0"):
        header, separator, name = entry.partition(b"\t")
        if separator and not header.startswith(b"160000 "):
            files.add(os.fsdecode(name))
    files.update(os.fsdecode(item) for item in untracked.split(b"\0") if item)
    return files


class _Collector:
    def __init__(self, root: Path, sources: list[SourceFile], listing: set[str] | None, *,
                 max_files: int, max_bytes: int, max_file_bytes: int, max_listed: int) -> None:
        self.root = root
        self.sources = sources
        self.listing = listing
        self.selected = {source.path for source in sources}
        self.texts = {source.path: source.after for source in sources if source.after is not None}
        self.max_files, self.max_bytes, self.max_file_bytes = max_files, max_bytes, max_file_bytes
        self.max_listed = max_listed
        self.files: list[RelatedFile] = []
        self.context: list[SourceFile] = []
        self.added: dict[str, str] = {}
        self.omissions: list[str] = []
        self.used = 0
        self.listed = 0
        self._cache: dict[str, str | None] = {}
        self._aliases: dict[str, AliasConfig | None] = {}

    # ---- files ------------------------------------------------------------------------------

    def eligible(self, path: str) -> bool:
        if not path or path.startswith(("../", "/")) or path in (".", ".."):
            return False
        if any(part in PRUNED_DIRECTORIES or part.endswith(".egg-info") for part in path.split("/")[:-1]):
            return False
        if self.listing is not None:
            return path in self.listing
        candidate = self.root / path
        return candidate.is_file() and not candidate.is_symlink()

    def read(self, path: str, limit: int) -> str | None:
        if path in self.texts:
            return self.texts[path]
        if path in self._cache:
            return self._cache[path]
        value = None
        if self.eligible(path):
            try:
                content = read_bytes(self.root / path, limit=limit)
                value = content.decode("utf-8") if content is not None else None
                if value is not None and "\0" in value:
                    value = None
            except (OSError, UnicodeError, IntegrationProblem):
                self.omissions.append("related_file_unreadable_symlink_binary_or_over_limit")
        self._cache[path] = value
        return value

    def add(self, path: str, reason: RelatedReason, *, analyze: bool = True) -> str | None:
        """Record a related file; analysis context is budgeted separately from listed-only files."""
        if path in self.selected:
            return self.texts.get(path)
        if path in self.added:
            return self.added[path]
        if analyze and len(self.context) >= self.max_files:
            self.omissions.append("related_file_count_limit")
            return None
        if not analyze and self.listed >= self.max_listed:
            return None
        remaining = min(self.max_file_bytes, self.max_bytes - self.used)
        if remaining <= 0:
            self.omissions.append("related_total_byte_limit")
            return None
        text = self.read(path, self.max_file_bytes)
        if text is None:
            return None
        size = len(text.encode("utf-8"))
        if size > remaining:
            self.omissions.append("related_total_byte_limit" if size <= self.max_file_bytes
                                  else "related_file_over_limit")
            return None
        self.used += size
        self.added[path] = text
        self.files.append(RelatedFile(path=path, digest=digest_text(text), bytes=size, reason=reason,
                                      used_for_analysis=analyze))
        if analyze:
            self.context.append(SourceFile(path, text, role="context"))
        else:
            self.listed += 1
        return text

    # ---- module resolution ------------------------------------------------------------------

    def alias(self, importer: str) -> tuple[str, AliasConfig] | None:
        for candidate in config_paths_for(importer):
            if candidate not in self._aliases:
                exists = candidate in self.texts or self.eligible(candidate)
                self._aliases[candidate] = load_alias_config(
                    candidate, lambda path: self.read(path, MAX_CONFIG_BYTES)) if exists else None
            loaded = self._aliases[candidate]
            if loaded is not None:
                return candidate, loaded
        return None

    def add_config(self, path: str, depth: int = 0) -> None:
        text = self.add(path, "tsconfig")
        if text is None or depth >= 4:
            return
        for parent in extends_targets(path, text):
            self.add_config(parent, depth + 1)

    def lookup(self, base: str) -> str | None:
        base = posixpath.normpath(base)
        if base.startswith("../") or base in (".", ".."):
            return None
        candidates = [base, *(base + extension for extension in JS_EXTENSIONS),
                      *(f"{base}/index{extension}" for extension in JS_EXTENSIONS)]
        stem, extension = posixpath.splitext(base)
        if extension in (".js", ".jsx", ".mjs", ".cjs"):
            candidates.extend(stem + replacement for replacement in (".ts", ".tsx", ".mts", ".cts"))
        for candidate in candidates:
            if posixpath.splitext(candidate)[1] in JS_EXTENSIONS and (
                    candidate in self.selected or self.eligible(candidate)):
                return candidate
        return None

    def resolve(self, importer: str, specifier: str) -> tuple[str, RelatedReason, str | None] | None:
        if specifier.startswith("."):
            found = self.lookup(posixpath.join(posixpath.dirname(importer), specifier))
            return (found, "relative_import", None) if found else None
        if specifier.startswith(("/", "node:")) or specifier.startswith(("http:", "https:")):
            return None
        governing = self.alias(importer)
        config_path, config = governing if governing is not None else (None, None)
        candidates = config.candidates(specifier) if config is not None else []
        if specifier.startswith(("@/", "~/")):
            rest = specifier[2:]
            anchors = dict.fromkeys([config.directory if config is not None else "", ""])
            candidates.extend(posixpath.join(anchor, prefix + rest) if anchor else prefix + rest
                              for anchor in anchors for prefix in ("src/", "", "app/"))
        for candidate in candidates:
            found = self.lookup(candidate)
            if found is not None:
                return found, "alias_import", config_path
        return None

    def imports_of(self, path: str, text: str) -> list[tuple[str, RelatedReason, str | None]]:
        results = []
        for match in JS_SPECIFIER.finditer(text[:MAX_SCAN_CHARS]):
            resolved = self.resolve(path, match.group(2))
            if resolved is not None:
                results.append(resolved)
        return results

    # ---- discovery --------------------------------------------------------------------------

    def forward(self, scripts: list[SourceFile]) -> None:
        """Imports of the reviewed files (and their imports), server-side helpers first."""
        frontier = [(source.path, source.after or "") for source in scripts[:MAX_SCANNED_SOURCES]]
        for depth in (1, 2):
            candidates: dict[str, tuple[int, RelatedReason, str | None]] = {}
            for importer, text in frontier:
                for path, reason, config_path in self.imports_of(importer, text):
                    if path in self.selected or path in self.added or TEST_FILE.search(path):
                        continue
                    rank = 0 if PRIORITY_PATH.search(path) and not path.endswith(".tsx") else (
                        1 if not path.endswith((".tsx", ".jsx")) else 2)
                    if path not in candidates or rank < candidates[path][0]:
                        candidates[path] = (rank, reason, config_path)
            next_frontier = []
            for path, (_, reason, config_path) in sorted(candidates.items(), key=lambda item: (item[1][0], item[0])):
                if config_path is not None:
                    self.add_config(config_path)
                added = self.add(path, reason)
                if added is not None and depth == 1:
                    next_frontier.append((path, added))
            frontier = next_frontier
            if len(self.context) >= self.max_files:
                break

    def importers(self, scripts: list[SourceFile], max_importers: int) -> None:
        """Files that import a reviewed TS/JS file: they supply the values its exports receive."""
        if not scripts:
            return
        if len(scripts) > MAX_IMPORTER_SOURCES:
            self.omissions.append("importer_search_skipped_for_large_change")
            return
        names: set[str] = set()
        for source in scripts:
            stem = posixpath.splitext(posixpath.basename(source.path))[0]
            name = posixpath.basename(posixpath.dirname(source.path)) if stem == "index" else stem
            if name:
                names.add(name)
        patterns = sorted({f"/{name}{end}" for name in names for end in ("'", '"', ".js'", '.js"')})
        extensions = [f"*{extension}" for extension in JS_EXTENSIONS]
        limits = SnapshotLimits(max_git_output_bytes=8_000_000)
        grep = ("-c", "grep.threads=8", "grep", "-l", "-z", "-I")
        # One alternation is ~3x faster than many fixed strings: `/name'`, `/name"`, `/name.js'`...
        alternation = "|".join(re.sub(r"([\\^$.|?*+()\[\]{}/-])", r"\\\1", name) for name in sorted(names))
        try:
            # Tracked files (their worktree content) through git grep; new untracked files are
            # listed and checked here, because `git grep --untracked` is about twice as slow.
            result = git_result(self.root, *grep, "-P", f"/({alternation})(\\.js)?['\"]", "--", *extensions,
                                limits=limits)
            if result.returncode not in (0, 1):  # Git without PCRE: the same needles as fixed strings
                arguments = [item for needle in patterns for item in ("-e", needle)]
                result = git_result(self.root, *grep, "-F", *arguments, "--", *extensions, limits=limits)
            if result.returncode not in (0, 1):
                raise IntegrationProblem("importer search failed")
            output = result.stdout if result.returncode == 0 else b""
            untracked = git_bytes(self.root, "ls-files", "--others", "--exclude-standard", "-z", "--",
                                  *extensions, allow_failure=True, limits=limits)
        except IntegrationProblem:
            self.omissions.append("importer_search_unavailable")
            return
        targets = {source.path for source in scripts}
        found = 0
        tests = 0
        candidates = {os.fsdecode(item) for item in output.split(b"\0") if item}
        new_files = [os.fsdecode(item) for item in untracked.split(b"\0") if item]
        if len(new_files) > MAX_UNTRACKED_SCAN:
            self.omissions.append("importer_search_untracked_limit")
        for name in new_files[:MAX_UNTRACKED_SCAN]:
            text = self.read(name, self.max_file_bytes)
            if text is not None and any(needle in text for needle in patterns):
                candidates.add(name)
        for candidate in sorted(candidates)[:MAX_IMPORTER_CANDIDATES]:
            if candidate in self.selected or candidate in self.added or not self.eligible(candidate):
                continue
            text = self.read(candidate, self.max_file_bytes)
            if text is None:
                continue
            if not any(path in targets for path, _, _ in self.imports_of(candidate, text)):
                continue
            if TEST_FILE.search(candidate):
                if tests < 4 and self.add(candidate, "test_candidate", analyze=False) is not None:
                    tests += 1
                continue
            if found >= max_importers:
                self.omissions.append("importer_limit")
                break
            governing = self.alias(candidate)
            if governing is not None:
                self.add_config(governing[0])
            if self.add(candidate, "importer") is not None:
                found += 1

    def python(self, sources: list[SourceFile]) -> None:
        for source in sources[:64]:
            path = Path(source.path)
            for match in PY_IMPORT.finditer((source.after or "")[:MAX_SCAN_CHARS]):
                name = match.group(1)
                dots = len(name) - len(name.lstrip("."))
                package = name[dots:].replace(".", "/")
                base = path.parent.as_posix() if dots else "."
                for _ in range(max(0, dots - 1)):
                    base = posixpath.dirname(base)
                for candidate in (f"{base}/{package}.py", f"{base}/{package}/__init__.py",
                                  f"src/{package}.py", f"src/{package}/__init__.py"):
                    normalized = posixpath.normpath(candidate)
                    if self.eligible(normalized):
                        self.add(normalized, "python_import", analyze=False)
                        break

    def tests_and_manifests(self) -> None:
        for source in self.sources[:32]:
            path = Path(source.path)
            if path.suffix not in (*JS_EXTENSIONS, ".py", ".rs"):
                continue
            for candidate in (
                path.with_name(f"{path.stem}.test{path.suffix}").as_posix(),
                path.with_name(f"{path.stem}.spec{path.suffix}").as_posix(),
                (path.parent / "__tests__" / path.name).as_posix(),
                f"tests/test_{path.stem}.py",
                f"tests/{path.stem}.test{path.suffix}",
                f"tests/{path.stem}.spec{path.suffix}",
            ):
                if self.eligible(candidate):
                    self.add(candidate, "test_candidate", analyze=False)
        for manifest in MANIFESTS:
            if self.eligible(manifest):
                self.add(manifest, "project_manifest", analyze=False)


def collect_related(
    root: Path, sources: Iterable[SourceFile], *, listing: set[str] | None = None,
    max_files: int = 40, max_bytes: int = 1_400_000, max_file_bytes: int = 500_000,
    max_listed: int = 12, max_importers: int = 16, importers: bool = True,
) -> tuple[ContextSummary, list[SourceFile]]:
    """Related-file summary plus context sources for the analyzers, within the given budget.

    `importers=False` skips the reverse-importer search, which needs Git (`git grep`): a plain
    folder review selects every file, so its importers are already reviewed.
    """
    if not (0 <= max_files <= 48 and 1 <= max_file_bytes <= max_bytes <= 1_500_000
            and 0 <= max_listed <= 32 and 0 <= max_importers <= 64):
        raise ValueError("invalid context bounds")
    reviewed = [source for source in sources if source.role == "review"]
    collector = _Collector(root.resolve(), reviewed, listing, max_files=max_files, max_bytes=max_bytes,
                           max_file_bytes=max_file_bytes, max_listed=max_listed)
    scripts = [source for source in reviewed
               if source.after is not None and source.skip is None and source.path.endswith(JS_EXTENSIONS)]
    collector.forward(scripts)
    if importers:
        collector.importers(scripts, max_importers)
    collector.python([source for source in reviewed if source.after is not None and source.path.endswith(".py")])
    collector.tests_and_manifests()
    summary = ContextSummary(files=collector.files, bytes_read=collector.used,
                             omissions=list(dict.fromkeys(collector.omissions)))
    return summary, collector.context


def related_context(
    root: Path, sources: Iterable[SourceFile], *, eligible_paths: set[str],
    max_files: int = 12, max_bytes: int = 128_000, max_file_bytes: int = 32_000,
) -> ContextSummary:
    """Compatibility wrapper: summary only, restricted to `eligible_paths`."""
    if not (1 <= max_files <= 48 and 1 <= max_file_bytes <= max_bytes <= 1_500_000):
        raise ValueError("invalid context bounds")
    summary, _ = collect_related(root, sources, listing=eligible_paths, max_files=max_files,
                                 max_bytes=max_bytes, max_file_bytes=max_file_bytes)
    return summary
