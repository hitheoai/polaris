"""Content-bound freshness, not a CI attestation or a claim of complete security coverage.

Every non-ignored tracked/untracked file participates, regardless of language. Known root
dependency/configuration files also participate when ignored. Installed dependencies, ignored
generated trees, external files and submodule contents are explicitly outside this snapshot.
Callers must supply their actual check matrix, trusted policy and analyzer/model versions.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from polaris import __version__
from polaris.integrations._safe import (
    IntegrationProblem,
    ProcessResult,
    atomic_write,
    no_symlinks,
    offline_environment,
    read_bytes,
    run_bounded,
)

SNAPSHOT_FORMAT = "polaris.snapshot/0.1.0"
RECEIPT_FORMAT = "polaris.local-review/0.1.0"
KNOWN_CONTEXT = (
    ".polaris.toml", "pyproject.toml", "uv.lock", "requirements.txt", "requirements-dev.txt",
    "Pipfile", "Pipfile.lock", "poetry.lock", "setup.cfg", "setup.py",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "pnpm-workspace.yaml", "bun.lock", "bun.lockb", "tsconfig.json", "jsconfig.json",
    ".npmrc", ".yarnrc.yml", ".env", ".env.local", ".env.production", ".gitignore",
    ".gitattributes", ".gitmodules", "AGENTS.md", "WARP.md", "CLAUDE.md", ".mcp.json",
    ".warp/.mcp.json", ".cursor/mcp.json", ".cursor/hooks.json", ".claude/settings.json",
    ".claude/settings.local.json", ".vscode/mcp.json", ".polaris/baseline.json",
)
OMITTED_SCOPE = (
    "Git-ignored content except known root dependency/configuration files and explicit extra_paths.",
    "Installed dependency contents, external configuration/includes, environment and network state.",
    "Submodule contents and symlink targets are not followed; listed omissions prevent freshness.",
    "Git administration is not source content; only local config/excludes and HEAD/index identity are bound.",
)
SCOPED_OMITTED_SCOPE = (
    "Only reviewed source and configuration files, their related context and known project "
    "configuration are bound; documentation, assets and other repository files can change "
    "without making this review stale.",
    "Installed dependency contents, external configuration/includes, environment and network state.",
    "Symlink targets are not followed; listed omissions prevent freshness.",
)
PATHSPEC_LIMIT = 400


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class SnapshotLimits:
    max_files: int = 10_000
    max_file_bytes: int = 2_000_000
    max_total_bytes: int = 64_000_000
    max_git_output_bytes: int = 4_000_000
    git_timeout: float = 10.0

    def __post_init__(self) -> None:
        if (not 1 <= self.max_files <= 100_000 or not 1 <= self.max_file_bytes <= 20_000_000
                or not 1 <= self.max_total_bytes <= 1_024_000_000
                or not 1 <= self.max_git_output_bytes <= 64_000_000
                or not 0 < self.git_timeout <= 30):
            raise IntegrationProblem("Invalid snapshot bounds.")


def scoped_limits(scope_size: int) -> SnapshotLimits:
    """Bounds for a scoped snapshot; derived only from the scope size so every caller agrees.

    Lockfiles and large generated sources are hashed (up to 20 MB each) instead of being
    reported as omissions that would make every review in a big repository incomplete.
    """
    return SnapshotLimits(
        max_files=min(100_000, max(10_000, scope_size + len(KNOWN_CONTEXT) + 8)),
        max_file_bytes=20_000_000, max_total_bytes=1_024_000_000,
    )


def _scoped_entries(output: bytes, keep: set[str], *, staged: bool) -> bytes:
    """Keep only NUL-separated `ls-files` records for scoped paths."""
    kept = []
    for entry in output.split(b"\0"):
        if not entry:
            continue
        name = entry.split(b"\t", 1)[1] if staged and b"\t" in entry else entry
        if os.fsdecode(name) in keep:
            kept.append(entry + b"\0")
    return b"".join(kept)


@dataclass(frozen=True)
class SnapshotFile:
    path: str
    digest: str | None
    size: int
    mode: int
    kind: str
    origin: str


@dataclass(frozen=True)
class SnapshotOmission:
    path: str
    reason: str


@dataclass(frozen=True)
class RepositoryIdentity:
    root: Path
    git_dir: Path
    common_dir: Path
    repository_id: str
    worktree_id: str


@dataclass(frozen=True)
class ReviewSnapshot:
    digest: str
    repository_id: str
    worktree_id: str
    root: str
    git_dir: str
    head: str | None
    index_digest: str
    provenance_digest: str
    files: tuple[SnapshotFile, ...]
    omissions: tuple[SnapshotOmission, ...]
    complete: bool
    omitted_scope: tuple[str, ...] = OMITTED_SCOPE
    format: str = SNAPSHOT_FORMAT

    def to_dict(self) -> dict[str, Any]:
        """JSON-compatible hashes and metadata only; never source or policy text."""
        return json.loads(_json(asdict(self)))


def git_result(root: Path, *args: str, limits: SnapshotLimits | None = None) -> ProcessResult:
    """Read-only Git with fsmonitor/external helpers and inherited Git overrides disabled."""
    limits = limits or SnapshotLimits()
    executable = shutil.which("git", path=os.defpath)
    if executable is None:
        raise IntegrationProblem("Git is unavailable.")
    env = offline_environment(Path(tempfile.gettempdir()))
    return run_bounded(
        [executable, "--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
         "-c", f"core.hooksPath={os.devnull}", "-c", "diff.external=", "-c", "credential.helper=",
         "-C", str(root), *args],
        cwd=root, env=env, timeout=limits.git_timeout, max_output_bytes=limits.max_git_output_bytes,
    )


def git_bytes(root: Path, *args: str, limits: SnapshotLimits | None = None,
              allow_failure: bool = False) -> bytes:
    """Read-only Git with fsmonitor/external helpers and inherited Git overrides disabled."""
    result = git_result(root, *args, limits=limits)
    if result.returncode and not allow_failure:
        raise IntegrationProblem("Git could not read this repository within the configured bounds.")
    return result.stdout if result.returncode == 0 else b""


def repository_identity(root: Path) -> RepositoryIdentity:
    root = no_symlinks(root)
    if not root.is_dir():
        raise IntegrationProblem("Project root is not a directory.")
    top = no_symlinks(Path(os.fsdecode(git_bytes(root, "rev-parse", "--show-toplevel").strip())))
    if not root.is_relative_to(top):
        raise IntegrationProblem("Git redirected the configured directory to a different worktree.")
    no_symlinks(top / ".git")
    git_dir = no_symlinks(Path(os.fsdecode(git_bytes(
        top, "rev-parse", "--absolute-git-dir").strip())))
    common_value = Path(os.fsdecode(git_bytes(top, "rev-parse", "--git-common-dir").strip()))
    common = no_symlinks(common_value if common_value.is_absolute() else top / common_value)
    return RepositoryIdentity(
        top, git_dir, common, _digest(os.fsencode(common)),
        _digest(os.fsencode(top) + b"\0" + os.fsencode(git_dir)),
    )


def _installed_analysis() -> dict[str, str]:
    """Bind the installed implementation, not merely a mutable marketing version string."""
    package = Path(__file__).resolve().parents[1]
    material: list[tuple[str, str]] = []
    for folder in ("review", "analysis", "analyzers"):
        directory = package / folder
        if directory.is_dir():
            for path in sorted(directory.rglob("*")):
                if path.suffix in (".py", ".yaml", ".yml", ".json") and not path.is_symlink():
                    value = read_bytes(path, limit=2_000_000)
                    if value is not None:
                        material.append((path.relative_to(package).as_posix(), _digest(value)))
    return {"polaris": __version__, "installed_analysis": _digest(_json(material))}


def _default_matrix() -> dict[str, Any]:
    # Conservative compatibility scope. New workflow callers pass the actual analyzer manifest.
    from polaris.review.engine import ANALYZABLE

    return {"python": sorted(ANALYZABLE), "model": "not_requested",
            "scope": "legacy Python static rules; caller must supply any broader capability matrix"}


def capture_snapshot(
    root: Path, *, policy: Any = None, check_matrix: Any = None,
    analyzer_versions: Mapping[str, Any] | None = None,
    model_versions: Mapping[str, Any] | None = None,
    extra_paths: Sequence[str | Path] = (), limits: SnapshotLimits | None = None,
    scope: Sequence[str] | None = None,
) -> ReviewSnapshot:
    """Hash declared source/context and review provenance without executing repository code.

    Without `scope`, every non-ignored file participates (bounded by `limits`). With `scope`,
    only those relative paths plus known project configuration are hashed, and HEAD/index
    entries are bound for the same paths, so unrelated edits elsewhere don't invalidate the
    review and large repositories stay cheap. `complete` means complete *within omitted_scope
    and limits*, not fully reviewed. Policy values are hashed, never serialized.
    """
    limits = limits or SnapshotLimits()
    identity = repository_identity(root)
    root = identity.root
    scoped = scope is not None
    selected = sorted({item for item in (scope or ()) if item and not item.startswith("__polaris")})
    omitted = SCOPED_OMITTED_SCOPE if scoped else OMITTED_SCOPE
    provenance = {
        "policy": policy, "check_matrix": _default_matrix() if check_matrix is None else check_matrix,
        "analyzer_versions": _installed_analysis() if analyzer_versions is None else dict(analyzer_versions),
        "model_versions": {"model": "not_requested"} if model_versions is None else dict(model_versions),
        "limits": asdict(limits), "omitted_scope": omitted,
        **({"scope": selected} if scoped else {}),
    }
    provenance_digest = _digest(_json(provenance))
    head = git_bytes(root, "rev-parse", "--verify", "HEAD", allow_failure=True).strip() or None
    pathspec: tuple[str, ...] = ()
    keep: set[str] | None = None
    git_limits = limits
    if scoped:
        keep = {*selected, *KNOWN_CONTEXT}
        if len(keep) <= PATHSPEC_LIMIT:
            pathspec = ("--", *(f":(literal){item}" for item in sorted(keep)))
        else:
            # Too many paths for a command line: list everything once and filter locally.
            git_limits = replace(limits, max_git_output_bytes=64_000_000)

    def inventory() -> tuple[bytes, bytes]:
        staged = git_bytes(root, "ls-files", "--stage", "-z", *pathspec, limits=git_limits)
        listed = git_bytes(root, "ls-files", "--cached", "--others", "--exclude-standard", "-z",
                           *pathspec, limits=git_limits)
        if keep is not None:
            return _scoped_entries(staged, keep, staged=True), _scoped_entries(listed, keep, staged=False)
        return staged, listed

    index, listing = inventory()
    if scoped:
        names = {name: "selected" for name in selected}
    else:
        names = {os.fsdecode(item): "repository" for item in listing.split(b"\0") if item}
    # Include missing known files, so creation/removal also changes the digest.
    names.update({name: names.get(name, "known_context") for name in KNOWN_CONTEXT})
    for item in extra_paths:
        candidate = Path(item)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(root)
            except ValueError as exc:
                raise IntegrationProblem("Extra context must stay within this worktree.") from exc
        if ".." in candidate.parts or ".git" in candidate.parts:
            raise IntegrationProblem("Extra context must stay within reviewed source scope.")
        names[candidate.as_posix()] = "explicit_context"
    files: list[SnapshotFile] = []
    omissions: list[SnapshotOmission] = []
    used = 0
    for position, (name, origin) in enumerate(sorted(names.items())):
        if position >= limits.max_files:
            omissions.append(SnapshotOmission("*", f"file_count_limit:{len(names) - position}"))
            break
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or ".git" in relative.parts:
            omissions.append(SnapshotOmission(name, "unsafe_path"))
            continue
        path = root / relative
        try:
            no_symlinks(path)
            info = path.stat() if path.exists() else None
            if info is None:
                files.append(SnapshotFile(name, _digest(b"missing"), 0, 0, "missing", origin))
                continue
            if not stat.S_ISREG(info.st_mode):
                omissions.append(SnapshotOmission(name, "directory_submodule_or_special_file"))
                files.append(SnapshotFile(name, None, 0, info.st_mode & 0o777, "omitted", origin))
                continue
            if info.st_size > limits.max_file_bytes or used + info.st_size > limits.max_total_bytes:
                reason = "file_byte_limit" if info.st_size > limits.max_file_bytes else "total_byte_limit"
                omissions.append(SnapshotOmission(name, reason))
                files.append(SnapshotFile(name, None, info.st_size, info.st_mode & 0o777, "omitted", origin))
                continue
            content = read_bytes(path, limit=limits.max_file_bytes)
            if content is None:
                raise IntegrationProblem("File disappeared during snapshot.")
            used += len(content)
            files.append(SnapshotFile(name, _digest(content), len(content), info.st_mode & 0o777,
                                      "file", origin))
        except (OSError, IntegrationProblem):
            omissions.append(SnapshotOmission(name, "unreadable_symlink_or_changed"))
            files.append(SnapshotFile(name, None, 0, 0, "omitted", origin))
    # Config/exclude files affect selection and Git behavior, but receipts/locks/index timestamps do not.
    for label, path in (("@git/config", identity.common_dir / "config"),
                        ("@git/config.worktree", identity.git_dir / "config.worktree"),
                        ("@git/info/exclude", identity.common_dir / "info" / "exclude")):
        try:
            content = read_bytes(path, limit=limits.max_file_bytes)
            if content is not None and used + len(content) > limits.max_total_bytes:
                raise IntegrationProblem("Total snapshot byte limit exceeded.")
            files.append(SnapshotFile(label, _digest(content if content is not None else b"missing"),
                                      len(content or b""), 0, "file" if content is not None else "missing",
                                      "git_context"))
            used += len(content or b"")
        except (OSError, IntegrationProblem):
            omissions.append(SnapshotOmission(label, "unreadable_or_limit"))
    if ((index, listing) != inventory()
            or head != (git_bytes(root, "rev-parse", "--verify", "HEAD", allow_failure=True).strip() or None)):
        omissions.append(SnapshotOmission("*", "repository_changed_during_snapshot"))
    head_text = os.fsdecode(head) if head else None
    index_digest = _digest(index)
    body = {
        "format": SNAPSHOT_FORMAT, "repository_id": identity.repository_id,
        "worktree_id": identity.worktree_id, "head": head_text,
        "index_digest": index_digest, "provenance_digest": provenance_digest,
        "files": [asdict(item) for item in files], "omissions": [asdict(item) for item in omissions],
    }
    return ReviewSnapshot(
        digest=_digest(_json(body)), repository_id=identity.repository_id, worktree_id=identity.worktree_id,
        root=str(root), git_dir=str(identity.git_dir), head=head_text, index_digest=index_digest,
        provenance_digest=provenance_digest, files=tuple(files), omissions=tuple(omissions),
        complete=not omissions, omitted_scope=omitted,
    )


def is_fresh(previous: ReviewSnapshot | Mapping[str, Any], current: ReviewSnapshot) -> bool:
    """Local UX only. Never use a caller-authored snapshot/receipt as required CI evidence."""
    data = previous.to_dict() if isinstance(previous, ReviewSnapshot) else previous
    if isinstance(data.get("snapshot"), Mapping):
        data = data["snapshot"]
    return bool(
        current.complete and data.get("complete") is True and data.get("format") == SNAPSHOT_FORMAT
        and data.get("digest") == current.digest
        and data.get("repository_id") == current.repository_id
        and data.get("worktree_id") == current.worktree_id
        and data.get("provenance_digest") == current.provenance_digest
    )


def state_directory(root: Path) -> Path:
    """Git's per-worktree admin directory is never tracked or part of the content snapshot."""
    identity = repository_identity(root)
    return no_symlinks(identity.git_dir / "polaris-agent" / identity.worktree_id.removeprefix("sha256:"))


def write_receipt(snapshot: ReviewSnapshot, summary: Mapping[str, Any]) -> Path:
    """Store hash metadata and a bounded *redacted* summary supplied by reporting.py."""
    path = state_directory(Path(snapshot.root)) / "review.json"
    brief = {key: value for key, value in snapshot.to_dict().items() if key not in ("files", "git_dir", "root")}
    value = {"format": RECEIPT_FORMAT, "trust": "mutable_local_hint_not_ci_evidence",
             "snapshot": brief, "summary": dict(summary)}
    content = _json(value)
    if len(content) > 1_000_000:
        raise IntegrationProblem("Local receipt exceeds its byte limit.")
    atomic_write(path, content + b"\n")
    return path


def read_receipt(root: Path) -> dict[str, Any] | None:
    value = read_bytes(state_directory(root) / "review.json", limit=1_000_000)
    if value is None:
        return None
    try:
        result = json.loads(value)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if not isinstance(result, dict) or result.get("format") != RECEIPT_FORMAT:
        return None
    return result
