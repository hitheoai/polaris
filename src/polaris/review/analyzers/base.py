"""Language-neutral input/output boundaries for read-only static analyzers."""

from __future__ import annotations

import fnmatch
import math
import os
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Any, Literal, Protocol

from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    EntryPoint,
    Language,
    SourceFile,
    WorkflowFinding,
    WorkflowReviewConfig,
)

_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


@dataclass(frozen=True)
class SourceKind:
    """A reviewable file type: how its paths are recognized and which checks can apply.

    `name` is the coverage `language` value. Checks declare the `domain`s they apply to (see
    `catalog.applies`), so a check for CI workflows never creates coverage rows or gaps on
    TypeScript files, and the reverse. Path patterns are matched first, then exact file names,
    then extensions, so `.github/workflows/*.yml` wins over any generic YAML kind. In patterns,
    `*` stays within one directory and `**` spans any number of them (`**/Dockerfile.*`).
    """

    name: str
    domain: str = "code"
    extensions: tuple[str, ...] = ()
    filenames: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not _NAME.fullmatch(self.name) or self.name == "unsupported" or not _NAME.fullmatch(self.domain):
            raise ValueError("source kind names and domains are short lowercase identifiers")
        if not (self.extensions or self.filenames or self.patterns):
            raise ValueError("a source kind needs at least one extension, file name or path pattern")
        if any(not re.fullmatch(r"\.[a-z0-9]{1,15}", item) for item in self.extensions):
            raise ValueError("extensions are lowercase and start with a dot")
        if any(not item or "/" in item or item in (".", "..") or len(item) > 128 for item in self.filenames):
            raise ValueError("file names are plain base names")
        if any(not item or len(item) > 256 or item.startswith("/") or ".." in item.split("/")
               or item.count("**") > 2 for item in self.patterns):
            raise ValueError("path patterns are relative repository globs")


_KINDS: dict[str, SourceKind] = {}


def register_kind(kind: SourceKind) -> SourceKind:
    """Add a source kind. Registering the identical kind again is a no-op; a different kind
    under the same name, or an extension/file name/pattern another kind claims, is refused so
    a file never silently changes analyzer."""
    current = _KINDS.get(kind.name)
    if current == kind:
        return kind
    if current is not None:
        raise ValueError(f"source kind {kind.name!r} is already registered differently")
    for other in _KINDS.values():
        if (set(other.extensions) & set(kind.extensions) or set(other.filenames) & set(kind.filenames)
                or set(other.patterns) & set(kind.patterns)):
            raise ValueError(f"source kind {kind.name!r} overlaps {other.name!r}")
    _KINDS[kind.name] = kind
    return kind


def _discard_kind(name: str) -> None:
    """Undo a registration (a plugin whose analyzer could not be registered)."""
    _KINDS.pop(name, None)


# Registered here, not by their analyzers, so classifying a path never depends on import order.
for _builtin in (
    SourceKind("python", extensions=(".py",)),
    SourceKind("javascript", extensions=(".js", ".jsx", ".mjs", ".cjs")),
    SourceKind("typescript", extensions=(".ts", ".tsx", ".mts", ".cts")),
    SourceKind("rust", extensions=(".rs",)),
    # Only the top level of .github/workflows, the files GitHub actually runs.
    SourceKind("github_actions", domain="ci",
               patterns=(".github/workflows/*.yml", ".github/workflows/*.yaml")),
    SourceKind("dockerfile", domain="container", extensions=(".dockerfile",),
               filenames=("Dockerfile", "Containerfile"),
               patterns=("**/Dockerfile.*", "**/Containerfile.*")),
):
    register_kind(_builtin)


def source_kinds() -> tuple[SourceKind, ...]:
    return tuple(_KINDS.values())


def source_kind(language: str) -> SourceKind | None:
    return _KINDS.get(language)


# Program source in languages Polaris does not analyze yet: changes here are unreviewed scope.
UNSUPPORTED_SOURCE = frozenset({
    ".go", ".java", ".kt", ".kts", ".swift", ".rb", ".php", ".c", ".h", ".cc", ".cpp",
    ".cxx", ".hpp", ".hh", ".cs", ".scala", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".pl",
    ".pm", ".lua", ".dart", ".ex", ".exs", ".erl", ".clj", ".cljs", ".groovy", ".r", ".m",
    ".mm", ".vue", ".svelte", ".astro", ".zig", ".nim", ".jl", ".fs", ".fsx", ".vb", ".sol",
})
FileKind = Literal["supported", "unsupported_source", "non_source"]
GENERATED_MARKERS = (".min.js", ".min.mjs", ".min.cjs", ".bundle.js", ".chunk.js")
GENERATED_PARTS = frozenset({"vendor", "third_party", "generated", "__generated__", ".next", "coverage"})


def path_matches(path: str, pattern: str) -> bool:
    """Repository glob: `*`, `?` and `[...]` stay within one path segment; `**` spans any number."""
    return _segments_match(path.split("/"), pattern.split("/"))


def _segments_match(parts: list[str], patterns: list[str]) -> bool:
    if not patterns:
        return not parts
    head, rest = patterns[0], patterns[1:]
    if head == "**":
        return any(_segments_match(parts[index:], rest) for index in range(len(parts) + 1))
    return bool(parts) and fnmatch.fnmatchcase(parts[0], head) and _segments_match(parts[1:], rest)


def language_for_path(path: str) -> Language:
    """The registered source kind for a relative path, or "unsupported"."""
    kinds = _KINDS.values()
    for kind in kinds:
        if kind.patterns and any(path_matches(path, pattern) for pattern in kind.patterns):
            return kind.name
    name = PurePosixPath(path).name
    for kind in kinds:
        if name in kind.filenames:
            return kind.name
    suffix = PurePosixPath(path).suffix.lower()
    return next((kind.name for kind in kinds if suffix in kind.extensions), "unsupported")


def file_kind(path: str) -> FileKind:
    """Classify a path for coverage: analyzable source, unsupported source, or not source code.

    Documentation, configuration, data, lockfiles and assets are "non_source": a security
    review has nothing to analyze there, so they never make a review incomplete. Changed program
    files in languages Polaris cannot analyze remain visible, unreviewed scope.
    """
    if language_for_path(path) != "unsupported":
        return "supported"
    if PurePosixPath(path).suffix.lower() in UNSUPPORTED_SOURCE:
        return "unsupported_source"
    return "non_source"


def generated_reason(path: str, text: str | None) -> str | None:
    """Minified bundles, vendored copies and generated declarations are not reviewed as source."""
    lowered = path.lower()
    if lowered.endswith(GENERATED_MARKERS) or lowered.endswith(".d.ts") or lowered.endswith(".d.mts"):
        return "generated_or_minified"
    if any(part in GENERATED_PARTS for part in lowered.split("/")[:-1]) or ".generated." in lowered.rsplit("/", 1)[-1]:
        return "generated_or_vendored"
    kind = _KINDS.get(language_for_path(path))
    # Bundles are minified program code. A long-line CI workflow or Dockerfile still runs as
    # written, so its shape never makes it skippable: it is analyzed or fails closed.
    if text is not None and len(text) > 20_000 and (kind is None or kind.domain == "code"):
        lines = text.count("\n") + 1
        if len(text) / lines > 400:
            return "generated_or_minified"
    return None


def local_workers() -> int:
    """Worker processes for large local reviews: leave one core free, at most eight."""
    return max(0, min(8, (os.cpu_count() or 1) - 1))


@dataclass(frozen=True)
class AnalysisRuntime:
    """Trusted host settings, never read from repository code, policy prose, or model output.

    Set BOTH allow flags to False for a memory-only consumer. External analysis uses a
    private temporary HOME/CWD and source copies. It is never silently run without an OS
    network-denial sandbox. An explicit executable must be a trusted, installed Semgrep.
    `parallel_workers` > 1 lets the built-in TypeScript analyzer spread large reviews over
    spawned worker processes (local CLI/MCP hosts only; 0 keeps everything in-process).
    `plugins` names `polaris.analyzers` entry points the operator chose to load; nothing is
    discovered or loaded implicitly, because loading one runs its installed code.
    """

    allow_external_analyzers: bool = True
    allow_temporary_source_files: bool = True
    semgrep_executable: str | None = None
    timeout_seconds: float = 30.0
    version_timeout_seconds: float = 5.0
    max_output_bytes: int = 4_000_000
    max_results: int = 1_000
    max_memory_mb: int = 512
    per_file_timeout_seconds: int = 5
    parallel_workers: int = 0
    plugins: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        for value, ceiling in ((self.timeout_seconds, 300), (self.version_timeout_seconds, 30)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                raise ValueError("analyzer time limits must be finite numbers")
            if not 0 < value <= ceiling:
                raise ValueError("analyzer time limit outside supported bounds")
        for value, lower, upper in (
            (self.max_output_bytes, 1_024, 16_000_000),
            (self.max_results, 1, 10_000),
            (self.max_memory_mb, 64, 4_096),
            (self.per_file_timeout_seconds, 1, 60),
            (self.parallel_workers, 0, 32),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
                raise ValueError("analyzer resource limit outside supported bounds")
        if not isinstance(self.allow_external_analyzers, bool) or not isinstance(self.allow_temporary_source_files, bool):
            raise ValueError("analyzer runtime switches must be booleans")
        if self.semgrep_executable is not None and (
            not isinstance(self.semgrep_executable, str)
            or "\0" in self.semgrep_executable
            or not self.semgrep_executable
        ):
            raise ValueError("analyzer executable must be an absolute installed path")
        if (not isinstance(self.plugins, tuple) or len(self.plugins) > 16 or len(set(self.plugins)) != len(self.plugins)
                or any(not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", name)
                       for name in self.plugins)):
            raise ValueError("analyzer plugins are up to 16 distinct entry-point names")


def runtime_identity(runtime: AnalysisRuntime) -> dict[str, Any]:
    """Runtime settings that can change a result, for review and approval digests.

    The worker count only changes speed, so it is left out: a review keeps its identity on
    every machine and in every host. Loaded plugins change results, so they are bound (and
    left out when there are none, keeping earlier identities unchanged).
    """
    data = asdict(runtime)
    del data["parallel_workers"]
    if not data["plugins"]:
        del data["plugins"]
    return data


@dataclass(frozen=True)
class AnalyzerResult:
    findings: tuple[WorkflowFinding, ...] = ()
    coverage: tuple[CheckCoverage, ...] = ()
    capability: AnalyzerCapability | None = None
    notices: tuple[str, ...] = ()
    omissions: tuple[str, ...] = ()
    # Entry points the analyzer recognized in reviewed files (descriptive; see EntryPoint).
    surface: tuple[EntryPoint, ...] = ()


@dataclass(frozen=True)
class AnalysisInput:
    sources: Sequence[SourceFile]
    checks: Sequence[str]
    config: WorkflowReviewConfig = field(default_factory=WorkflowReviewConfig)
    workers: int = 0


class Analyzer(Protocol):
    """An adapter accepts only caller-provided source snapshots, never a project to execute."""

    analyzer_id: str

    def analyze(self, request: AnalysisInput) -> AnalyzerResult: ...
