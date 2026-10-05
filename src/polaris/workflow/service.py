"""Shared read-only workflow coordination for CLI, hooks, MCP and memory-only HTTP."""

from __future__ import annotations

import threading
from collections import Counter, OrderedDict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from polaris.integrations._safe import IntegrationProblem, read_bytes
from polaris.integrations.freshness import (
    ReviewSnapshot,
    capture_snapshot,
    is_fresh,
    scoped_limits,
)
from polaris.jsonio import digest_bytes, digest_json, digest_text
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.analyzers.base import file_kind, runtime_identity
from polaris.review.analyzers.registry import load_plugins
from polaris.review.capabilities import capability_manifest
from polaris.review.engine import WorkflowReviewer
from polaris.review.js.tsconfig import is_config
from polaris.review.models import (
    ImportedFinding,
    ProjectSettings,
    SourceFile,
    TrustedGuardPolicy,
    WorkflowReviewConfig,
    WorkflowReviewReport,
)
from polaris.review.project import (
    BASELINE_PATH,
    MAX_BASELINE_BYTES,
    MAX_SETTINGS_BYTES,
    SETTINGS_PATH,
    load_baseline,
    load_project_settings,
    parse_baseline,
    parse_project_settings,
)
from polaris.review.sarif_import import (
    SarifInput,
    at_least,
    by_tool,
    corroborations,
    import_sarif,
    unevaluated,
)
from polaris.review.scope import FOLDER_SKIPPED, SCOPE_LIMIT_PATH, VCS_DIRECTORIES, folder_files
from polaris.workflow.context import collect_related, repository_files
from polaris.workflow.models import (
    ChangeRecord,
    ContextSummary,
    SnapshotReference,
    WorkflowBrief,
    WorkflowDetailPage,
    WorkflowEnvelope,
)


def review_policy(
    config: WorkflowReviewConfig, guard_policy: TrustedGuardPolicy | None,
    runtime: AnalysisRuntime, *, staged: bool = False, revision_range: str | None = None,
    paths: list[Path] | None = None,
) -> dict[str, Any]:
    """Recompute configured runtime identity; never read configuration from source text."""
    launcher_digest = None
    if runtime.semgrep_executable is not None:
        try:
            content = read_bytes(Path(runtime.semgrep_executable), limit=2_000_000)
            launcher_digest = digest_bytes(content) if content is not None else "unavailable"
        except (OSError, IntegrationProblem):
            launcher_digest = "unavailable"
    return {
        "review_config": config.model_dump(mode="json"),
        "guard_policy": guard_policy.model_dump(mode="json") if guard_policy else None,
        "runtime": runtime_identity(runtime),
        "configured_launcher_digest": launcher_digest,
        "selection": {
            "staged": staged, "range": revision_range,
            "paths": [str(path) for path in paths] if paths is not None else None,
        },
    }


def _source_identity(sources: list[SourceFile]) -> str:
    return digest_json([
        {
            "path": item.path, "previous_path": item.previous_path,
            "before": digest_text(item.before) if item.before is not None else None,
            "after": digest_text(item.after) if item.after is not None else None,
            "skip": item.skip, "before_skip": item.before_skip,
            "lines": sorted(item.changed_lines) if item.changed_lines is not None else None,
            "context_complete": item.context_complete,
        }
        for item in sources
    ])


def _changes(sources: list[SourceFile], *, submitted: bool = False) -> list[ChangeRecord]:
    changes = []
    for source in sources:
        kind: Literal["added", "modified", "renamed", "deleted", "unreadable", "supplied"]
        if source.skip == "deleted":
            kind = "deleted"
        elif source.skip:
            kind = "unreadable"
        elif source.previous_path and source.previous_path != source.path:
            kind = "renamed"
        elif submitted:
            kind = "supplied"
        else:
            kind = "modified" if source.before is not None else "added"
        changes.append(ChangeRecord(
            path=source.path, previous_path=source.previous_path, kind=kind,
            before_digest=digest_text(source.before) if source.before is not None else None,
            after_digest=digest_text(source.after) if source.after is not None else None,
            changed_lines=len(source.changed_lines) if source.changed_lines is not None else None,
        ))
    return changes


def _reference(
    snapshot: ReviewSnapshot, *,
    kind: Literal["worktree", "git_index", "git_revision"], fresh: bool,
) -> SnapshotReference:
    data = snapshot.to_dict()
    return SnapshotReference(
        format=data["format"], kind=kind, digest=snapshot.digest,
        repository_id=snapshot.repository_id, worktree_id=snapshot.worktree_id,
        head=snapshot.head, index_digest=snapshot.index_digest,
        provenance_digest=snapshot.provenance_digest,
        complete=snapshot.complete, fresh=fresh, files_count=len(snapshot.files),
        omissions=data["omissions"], omitted_scope=data["omitted_scope"],
    )


def _envelope(
    report: WorkflowReviewReport, snapshot: SnapshotReference, sources: list[SourceFile],
    context: ContextSummary, *, stale: bool = False, extra_notices: Iterable[str] = (),
) -> WorkflowEnvelope:
    flagged = sum(finding.result == "flagged" for finding in report.findings)
    verify = sum(finding.result == "needs_context" for finding in report.findings)
    incomplete = not report.coverage.complete or not snapshot.complete
    status: Literal["complete", "incomplete", "stale", "error"] = (
        "stale" if stale else "incomplete" if incomplete else "complete"
    )
    reviewed = [source for source in sources if source.role == "review" and source.path != SCOPE_LIMIT_PATH]
    summary = (
        f"{flagged} issue(s) to fix, {verify} to verify in {len(reviewed)} file(s); "
        f"review {status}. Behavioral tests: not run."
    )
    notices = [
        "Static re-review is not proof of behavioral correctness or authorization to change or execute anything.",
        "Local report IDs and snapshot receipts are mutable hints, never trusted CI attestations.",
    ]
    if snapshot.kind == "submitted_content":
        notices.append("Only the submitted content is bound; no claim is made about the client's current worktree.")
    if stale:
        notices.append("Source, context, selection or analyzer configuration changed during review; re-review is required.")
    if not reviewed:
        notices.append("No selected changed files were found; this is not a review of the entire repository.")
    notices.extend(extra_notices)
    return WorkflowEnvelope(
        report_id=digest_json({"snapshot": snapshot.model_dump(mode="json"), "review": report.model_dump(mode="json")}),
        status=status, summary=summary, finding_count=flagged, snapshot=snapshot,
        changes=_changes(reviewed, submitted=snapshot.kind == "submitted_content"),
        context=context, review=report, notices=notices,
    )


def review_supplied(
    sources: Iterable[SourceFile], *, config: WorkflowReviewConfig | None = None,
    runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
) -> WorkflowEnvelope:
    """Review caller content without resolving labels as server filesystem paths.

    HTTP callers use the default memory-only runtime. An embedding application must
    explicitly choose otherwise; runtime or trusted policy is never read from source.
    """
    chosen = config or WorkflowReviewConfig()
    # Do not exhaust an unbounded iterator; the extra source makes truncation explicit.
    from itertools import islice

    files = list(islice(sources, chosen.max_files + 1))
    active_runtime = runtime or AnalysisRuntime(
        allow_external_analyzers=False, allow_temporary_source_files=False,
    )
    report = WorkflowReviewer(config=chosen, runtime=active_runtime, guard_policy=guard_policy).review_sources(files)
    snapshot = SnapshotReference(
        format="polaris.submitted-snapshot/0.1.0", kind="submitted_content",
        digest=report.provenance.snapshot_digest,
        provenance_digest=digest_json(report.provenance.model_dump(mode="json")),
        complete=len(files) <= chosen.max_files, fresh=None, files_count=len(files),
        omitted_scope=["Client repository, dependencies, prior revisions and files not submitted."],
    )
    return _envelope(
        report, snapshot, files,
        ContextSummary(omissions=["Related filesystem context is not retrieved by the submitted-content API."]),
    )


def review_scope(sources: Iterable[SourceFile]) -> list[str]:
    """Repository paths a workspace review binds: source and configuration files under review,
    their previous paths, and related context.

    Documentation and assets are never analyzed (their coverage is decided by path alone), so
    they can't change a result; hashing large media would also exhaust the snapshot budget
    before the source files it exists to bind.
    """
    scope = set()
    for source in sources:
        if source.path == SCOPE_LIMIT_PATH or source.path.startswith("__polaris"):
            continue
        if source.role == "review" and file_kind(source.path) == "non_source" and not is_config(source.path):
            continue
        scope.add(source.path)
        if source.previous_path:
            scope.add(source.previous_path)
    return sorted(scope)


def scoped_snapshot(
    root: Path, scope: list[str], *, policy: dict[str, Any], matrix: Any,
) -> ReviewSnapshot:
    """The one snapshot shape shared by reviews, repair proposals and hooks."""
    return capture_snapshot(
        root, policy=policy, check_matrix=matrix.model_dump(mode="json"),
        model_versions={"generation": "not_requested", "classifier": "not_requested"},
        scope=scope, limits=scoped_limits(len(scope)),
    )


def _snapshot_agrees(snapshot: ReviewSnapshot, sources: Iterable[SourceFile]) -> bool:
    """Context read from the worktree must be exactly the content the snapshot bound."""
    digests = {item.path: item.digest for item in snapshot.files}
    return all(source.after is not None and digests.get(source.path) == digest_text(source.after)
               for source in sources)


def expand_paths(root: Path, paths: list[Path], listing: set[str] | None) -> list[Path]:
    """Expand directory arguments to Git's non-ignored files; explicit files are kept as given.

    Build output, dependencies and other ignored trees (.next, target/, coverage/...) are
    never enumerated. Without a Git listing, the bounded filesystem walk is used instead.
    """
    if listing is None:
        return paths
    ordered = sorted(listing)
    expanded: list[Path] = []
    for path in paths:
        absolute = path if path.is_absolute() else root / path
        try:
            relative = absolute.relative_to(root).as_posix()
        except ValueError:
            expanded.append(path)  # reported as outside_root by the collector
            continue
        relative = "" if relative == "." else relative
        if relative and not (absolute.is_dir() and not absolute.is_symlink()):
            expanded.append(Path(relative))
            continue
        prefix = f"{relative}/" if relative else ""
        expanded.extend(Path(name) for name in ordered if name.startswith(prefix))
    return list(dict.fromkeys(expanded))


def project_config(root: Path, config: WorkflowReviewConfig) -> WorkflowReviewConfig:
    """Apply `.polaris.toml` [workflow] settings unless the caller supplied explicit ones."""
    if config.project != ProjectSettings():
        return config
    settings = load_project_settings(root)
    return config if settings == ProjectSettings() else config.model_copy(update={"project": settings})


@dataclass(frozen=True)
class WorkspaceReview:
    """A workspace review together with the exact inputs it analyzed.

    Integrations that re-review in memory (for example, to re-verify a suggested edit before
    offering it) need the same sources, related context, effective configuration and baseline.
    Source text stays in this process; nothing here is persisted or sent anywhere.
    """

    envelope: WorkflowEnvelope
    sources: tuple[SourceFile, ...]
    context_sources: tuple[SourceFile, ...]
    config: WorkflowReviewConfig
    baseline: frozenset[str]
    guard_policy: TrustedGuardPolicy | None
    # Folder reviews only: dependency and build folders that were skipped (relative paths).
    skipped: tuple[str, ...] = ()


def review_workspace(
    root: Path, *, staged: bool = False, revision_range: str | None = None,
    paths: list[Path] | None = None, config: WorkflowReviewConfig | None = None,
    runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
    use_project_settings: bool = True, use_baseline: bool = True, imports: Sequence[SarifInput] = (),
) -> WorkflowEnvelope:
    """Independently analyze actual sources and bind before/after snapshots of the reviewed scope.

    The snapshot covers the reviewed files (worktree and staged reviews), the related files
    analyzed as context and known project configuration, so unrelated edits elsewhere never make
    a review stale. Range reviews bind their commits instead of worktree copies. This does not
    read a prior local receipt and does not persist a report or source. `imports` are other
    tools' SARIF files: their results within the reviewed scope are attached as untrusted,
    unverified data and never change Polaris results or coverage.
    """
    return review_workspace_detailed(
        root, staged=staged, revision_range=revision_range, paths=paths, config=config, runtime=runtime,
        guard_policy=guard_policy, use_project_settings=use_project_settings, use_baseline=use_baseline,
        imports=imports,
    ).envelope


def review_workspace_detailed(
    root: Path, *, staged: bool = False, revision_range: str | None = None,
    paths: list[Path] | None = None, config: WorkflowReviewConfig | None = None,
    runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
    use_project_settings: bool = True, use_baseline: bool = True, imports: Sequence[SarifInput] = (),
) -> WorkspaceReview:
    """`review_workspace`, also returning the analyzed sources, context and effective settings."""
    from polaris.review.git import filter_scope

    with filter_scope():  # Git filter configuration is read once per review, never reused later
        return _review_workspace(
            root, staged=staged, revision_range=revision_range, paths=paths, config=config, runtime=runtime,
            guard_policy=guard_policy, use_project_settings=use_project_settings, use_baseline=use_baseline,
            imports=imports,
        )


def _review_workspace(
    root: Path, *, staged: bool, revision_range: str | None, paths: list[Path] | None,
    config: WorkflowReviewConfig | None, runtime: AnalysisRuntime | None, guard_policy: TrustedGuardPolicy | None,
    use_project_settings: bool, use_baseline: bool, imports: Sequence[SarifInput] = (),
) -> WorkspaceReview:
    from polaris.review.git import revision_identity, workflow_sources_from_git
    from polaris.review.scope import workflow_sources_from_paths

    if sum((staged, revision_range is not None, paths is not None)) > 1:
        raise ValueError("choose one of staged, revision range or paths")
    root = root.resolve()
    if root in (Path(root.anchor), Path.home().resolve()) or not root.is_dir():
        raise ValueError("review requires a bounded project directory")
    chosen = config or WorkflowReviewConfig()
    extra_notices: list[str] = []
    if revision_range is not None and (use_project_settings or use_baseline):
        # CI: settings and baseline come from the base revision, never from the change itself.
        from polaris.review.git import base_revision_files

        base, files = base_revision_files(
            root, revision_range, {SETTINGS_PATH: MAX_SETTINGS_BYTES, BASELINE_PATH: MAX_BASELINE_BYTES})
        settings_bytes, baseline_bytes = files[SETTINGS_PATH], files[BASELINE_PATH]
        if use_project_settings and chosen.project == ProjectSettings():
            settings = parse_project_settings(settings_bytes)
            if settings != ProjectSettings():
                chosen = chosen.model_copy(update={"project": settings})
        baseline = parse_baseline(baseline_bytes) if use_baseline else frozenset()
        if base is not None:
            extra_notices.append(f"Project settings and baseline were read from the base revision {base[:12]}.")
    else:
        if use_project_settings:
            chosen = project_config(root, chosen)
        baseline = load_baseline(root) if use_baseline else frozenset()
    active_runtime = runtime or AnalysisRuntime(
        allow_external_analyzers=True, allow_temporary_source_files=True,
    )
    # Explicitly requested plugins add source kinds, which decide how changed files are read.
    load_plugins(active_runtime.plugins)
    manifest = capability_manifest(runtime=active_runtime, probe=True)
    policy = review_policy(chosen, guard_policy, active_runtime, staged=staged,
                           revision_range=revision_range, paths=paths)

    listing = repository_files(root)
    selected_paths = expand_paths(root, paths, listing) if paths is not None else None

    def collect() -> list[SourceFile]:
        if selected_paths is not None:
            return workflow_sources_from_paths(selected_paths, root=root, config=chosen)
        return workflow_sources_from_git(
            root, staged=staged, revision_range=revision_range, config=chosen,
        )

    commits = revision_identity(root, revision_range) if revision_range is not None else None
    sources = collect()
    context, context_sources = collect_related(root, sources, listing=listing)
    # A range review reads changed files from immutable commits: only what it read from the
    # worktree (related context, project configuration) can go stale.
    scope = review_scope(context_sources if revision_range is not None else [*sources, *context_sources])
    before = scoped_snapshot(root, scope, policy=policy, matrix=manifest)
    report = WorkflowReviewer(
        config=chosen, runtime=active_runtime, guard_policy=guard_policy, baseline=baseline,
    ).review_sources([*sources, *context_sources])
    if imports:
        # Other tools' results, as untrusted data: bound into the report, never into coverage.
        report = import_sarif(report, imports, root=root, sources=sources)
    if revision_range is not None:
        # Commits never change: the selection is current while the range resolves to the same commits.
        selected = revision_identity(root, revision_range) == commits
    else:
        selected = _source_identity(sources) == _source_identity(collect())
    selected_unchanged = selected and _snapshot_agrees(before, context_sources)
    after = scoped_snapshot(root, scope, policy=policy,
                            matrix=capability_manifest(runtime=active_runtime, probe=True))
    fresh = selected_unchanged and is_fresh(before, after)
    kind: Literal["worktree", "git_index", "git_revision"] = (
        "git_index" if staged else "git_revision" if revision_range else "worktree"
    )
    envelope = _envelope(
        report, _reference(before, kind=kind, fresh=fresh), sources, context,
        stale=not selected_unchanged or before.digest != after.digest, extra_notices=extra_notices,
    )
    return WorkspaceReview(
        envelope=envelope, sources=tuple(sources), context_sources=tuple(context_sources),
        config=chosen, baseline=baseline, guard_policy=guard_policy,
    )


FOLDER_SNAPSHOT_FORMAT = "polaris.folder-snapshot/0.1.0"
FOLDER_OMITTED_SCOPE = (
    "A plain folder without Git: no commit, staging area or ignore rules are read, and nothing is "
    "recorded between reviews.",
    "Dependency, build and cache folders (node_modules, .next, dist, vendor, ...) are skipped by name; "
    "symlink targets are not followed.",
    "Installed dependency contents, external configuration/includes, environment and network state.",
)
FOLDER_SETTINGS = ((SETTINGS_PATH, MAX_SETTINGS_BYTES), (BASELINE_PATH, MAX_BASELINE_BYTES))


def _folder_settings(root: Path) -> str:
    """A digest of the project settings and baseline files, to notice a change during a review."""
    digests: list[str | None] = []
    for relative, limit in FOLDER_SETTINGS:
        try:
            content = read_bytes(root / relative, limit=limit)
            digests.append(digest_bytes(content) if content is not None else None)
        except (OSError, IntegrationProblem):
            digests.append("unreadable")
    return digest_json(digests)


def skipped_names(skipped: Iterable[str]) -> list[str]:
    """The kinds of folders a folder review skipped, by name. Only names from the fixed skip list
    are shown (never other text from the folder); version-control folders aren't worth naming."""
    return sorted({Path(path).name for path in skipped} & (FOLDER_SKIPPED - VCS_DIRECTORIES))


def _context_agrees(root: Path, sources: Iterable[SourceFile]) -> bool:
    from polaris.review.scope import read_scoped_text

    return all(read_scoped_text(root, source.path, 2_000_000)[0] == source.after for source in sources)


def review_folder_detailed(
    root: Path, *, paths: list[Path] | None = None, config: WorkflowReviewConfig | None = None,
    runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
    use_project_settings: bool = True, use_baseline: bool = True, imports: Sequence[SarifInput] = (),
) -> WorkspaceReview:
    """Review a folder that isn't a Git project, as plain files: bounded and read-only.

    A bounded walk stands in for Git's file list (dependency and build folders are skipped by
    name, links are never followed) and `paths` narrows it like `--files`. There is no Git
    snapshot: the envelope's snapshot is a digest of exactly what was read, and the review is
    stale when a second bounded read of the folder differs. Nothing here feeds CI gates, repair
    approvals or local receipts, which all need Git.
    """
    root = root.resolve()
    if root in (Path(root.anchor), Path.home().resolve()) or not root.is_dir():
        raise ValueError("review requires a bounded project directory")
    chosen = config or WorkflowReviewConfig()
    settings = _folder_settings(root)
    if use_project_settings:
        chosen = project_config(root, chosen)
    baseline = load_baseline(root) if use_baseline else frozenset()
    active_runtime = runtime or AnalysisRuntime(
        allow_external_analyzers=True, allow_temporary_source_files=True,
    )
    load_plugins(active_runtime.plugins)
    manifest = capability_manifest(runtime=active_runtime, probe=True)
    selection = paths if paths is not None else [root]
    policy = review_policy(chosen, guard_policy, active_runtime, paths=selection)
    from polaris.review.scope import workflow_sources_from_paths

    def collect() -> tuple[tuple[str, ...], tuple[str, ...], list[SourceFile]]:
        listing = folder_files(root, max_files=chosen.max_files)
        selected = expand_paths(root, selection, set(listing.files))
        sources = workflow_sources_from_paths(selected, root=root, config=chosen)
        if listing.truncated and not any(source.path == SCOPE_LIMIT_PATH for source in sources):
            # The walk stopped early: the rest of the folder is visible, unreviewed scope.
            sources.append(SourceFile(SCOPE_LIMIT_PATH, None, skip=listing.truncated))
        return listing.files, listing.skipped, sources

    files, skipped, sources = collect()
    context, context_sources = collect_related(root, sources, listing=set(files), importers=False)
    report = WorkflowReviewer(
        config=chosen, runtime=active_runtime, guard_policy=guard_policy, baseline=baseline,
    ).review_sources([*sources, *context_sources])
    if imports:
        report = import_sarif(report, imports, root=root, sources=sources)
    files_again, _, sources_again = collect()
    unchanged = (files_again == files and _source_identity(sources_again) == _source_identity(sources)
                 and _context_agrees(root, context_sources) and _folder_settings(root) == settings)
    limited = any(source.path == SCOPE_LIMIT_PATH for source in sources)
    snapshot = SnapshotReference(
        format=FOLDER_SNAPSHOT_FORMAT, kind="worktree",
        digest=digest_json({"format": FOLDER_SNAPSHOT_FORMAT, "files": list(files),
                            "sources": _source_identity(sources), "context": _source_identity(context_sources),
                            "settings": settings}),
        provenance_digest=digest_json({"policy": policy, "check_matrix": manifest.model_dump(mode="json")}),
        complete=not limited, fresh=None, files_count=len(files),
        omissions=[{"path": "*", "reason": "folder_limit"}] if limited else [],
        omitted_scope=list(FOLDER_OMITTED_SCOPE),
    )
    notices = ["This folder isn't a Git project, so it was reviewed as plain files, without a Git snapshot."]
    names = skipped_names(skipped)
    if names:
        notices.append("Skipped dependency and build folders: " + ", ".join(names[:12])
                       + (f" and {len(names) - 12} more" if len(names) > 12 else "") + ".")
    envelope = _envelope(report, snapshot, sources, context, stale=not unchanged, extra_notices=notices)
    return WorkspaceReview(
        envelope=envelope, sources=tuple(sources), context_sources=tuple(context_sources),
        config=chosen, baseline=baseline, guard_policy=guard_policy, skipped=skipped,
    )


REASON_TEXT = {
    "unsupported_language": "no analyzer for this language yet",
    "not_implemented_for_language": "check not implemented for this language",
    "file_too_large": "larger than the per-file size limit",
    "total_source_limit": "review size limit reached before this file",
    "file_limit": "more files than the review's file limit; the rest were not reviewed",
    "result_limit": "finding limit reached; more findings may exist",
    "partial_parse": "syntax errors; analyzed partially",
    "analysis_error": "analysis failed",
    "analysis_limit": "analysis depth limit reached",
    "memory_limit": "analysis memory limit reached",
    "analyzer_produced_no_result": "analyzer produced no result",
    "invalid_encoding": "not valid UTF-8",
    "binary": "binary content",
    "unreadable": "unreadable",
    "symlink": "symbolic link (not followed)",
    "unmerged": "unresolved merge conflict",
    "duplicate_source_path": "duplicate paths were supplied",
    "invalid_path": "invalid path",
}
SEVERITIES = ("critical", "high", "medium", "low", "info")


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def excluded_count(report: WorkflowEnvelope) -> int:
    """Files left out by include/exclude configuration (listed, never silently dropped)."""
    return len({entry.path for entry in report.review.coverage.entries if entry.reason == "excluded"})


def unreviewed_scope(report: WorkflowEnvelope) -> list[tuple[str, str]]:
    """(path, reason) for required coverage that did not complete, one row per path."""
    rows: dict[str, str] = {}
    for entry in report.review.coverage.entries:
        if entry.required and entry.status != "checked" and entry.path not in rows:
            rows[entry.path] = entry.reason
    return sorted(rows.items())


def brief_report(report: WorkflowEnvelope, *, limit: int = 12) -> WorkflowBrief:
    if not 0 <= limit <= 50:
        raise ValueError("invalid finding limit")
    coverage = report.review.coverage.model_dump(mode="json", exclude={"entries"})
    unreviewed = unreviewed_scope(report)
    # Only required rows make a review incomplete; documentation/assets are not_applicable.
    coverage["unreviewed_reasons"] = sorted({reason for _, reason in unreviewed} | set(report.review.coverage.omissions))
    coverage["unreviewed"] = [{"path": path, "reason": reason} for path, reason in unreviewed[:25]]
    coverage["files_excluded"] = excluded_count(report)
    return WorkflowBrief(
        report_id=report.report_id, status=report.status, summary=report.summary,
        finding_count=report.finding_count, findings=report.review.findings[:limit],
        findings_remaining=max(0, len(report.review.findings) - limit),
        coverage=coverage, snapshot=report.snapshot,
        changed_files=len(report.changes), related_files=report.context.files,
        notices=[*report.notices, *report.review.notices],
    )


def _location(finding: Any) -> str:
    symbol = finding.symbol if finding.symbol and finding.symbol != "<module>" else None
    return f"{finding.path}:{finding.start_line}" + (f" in {symbol}" if symbol else "")


def _snippet_lines(finding: Any, *, only_flagged: bool = False) -> list[str]:
    if not finding.snippet or not finding.snippet_start_line:
        return []
    lines = finding.snippet.splitlines()
    width = len(str(finding.snippet_start_line + len(lines)))
    end = finding.end_line or finding.start_line
    rendered = []
    for offset, text in enumerate(lines):
        number = finding.snippet_start_line + offset
        flagged = finding.start_line <= number <= max(finding.start_line, min(end, finding.start_line + 2))
        if only_flagged and number != finding.start_line:
            continue
        rendered.append(f"   {'>' if flagged else ' '} {number:>{width}} | {text}")
    return rendered


def _trace_text(finding: Any) -> str | None:
    steps = list(finding.trace or [])
    if len(steps) < 2:
        return None
    parts = []
    for step in steps:
        where = f"{step.path}:{step.line}" if step.path and step.path != finding.path else f"line {step.line}"
        parts.append(f"{step.label} ({where})")
    return " → ".join(parts)


def _also_reported(items: Sequence[ImportedFinding]) -> list[str]:
    """Imported results that corroborate a Polaris finding (presentation only)."""
    if not items:
        return []
    shown = ", ".join(f"{item.tool}{' ' + item.rule_id if item.rule_id else ''} (line {item.start_line})"
                      for item in items[:4])
    more = f" and {len(items) - 4} more" if len(items) > 4 else ""
    return [f"   Also reported by: {shown}{more} — imported SARIF, not verified by Polaris"]


def _finding_block(index: str, finding: Any, also: Sequence[ImportedFinding] = ()) -> list[str]:
    severity = (finding.severity or "medium").upper()
    lines = [f"{index} {severity} · {finding.title} · {_location(finding)}", f"   {finding.message}"]
    lines.extend(_snippet_lines(finding))
    trace = _trace_text(finding)
    if trace:
        lines.append(f"   Path: {trace}")
    if finding.guidance:
        lines.append(f"   Fix: {finding.guidance}")
    edit = finding.suggested_edit
    if edit is not None:
        lines.append(f"   Suggested edit (line {edit.line}){': ' + edit.note if edit.note else ''}")
        lines.append(f"     - {edit.original.strip()}")
        lines.append(f"     + {edit.replacement.strip()}")
    lines.extend(_also_reported(also))
    meta = [item for item in (finding.rule_id, finding.cwe, f"confidence {finding.confidence}" if finding.confidence else None,
                              f"id {finding.finding_id}") if item]
    lines.append("   " + " · ".join(meta))
    return lines


def _verify_block(index: str, finding: Any, also: Sequence[ImportedFinding] = ()) -> list[str]:
    severity = (finding.severity or "medium").upper()
    lines = [f"{index} {severity} · {finding.title} · {_location(finding)}", f"   {finding.message}"]
    lines.extend(_snippet_lines(finding, only_flagged=True))
    if finding.verify:
        lines.append(f"   Verify: {finding.verify}")
    if finding.call_sites:
        shown = ", ".join(finding.call_sites[:6])
        more = len(finding.call_sites) - 6
        lines.append(f"   Callers: {shown}" + (f" (+{more} more)" if more > 0 else ""))
    lines.extend(_also_reported(also))
    lines.append(f"   {finding.rule_id or finding.check_id} · id {finding.finding_id}")
    return lines


def imported_row(item: ImportedFinding) -> str:
    """One imported result as plain text (its fields are already bounded and printable)."""
    where = item.path + (f":{item.start_line}" if item.start_line else "")
    rating = f" · {item.category}"
    if item.security_severity is not None:
        rating += f" {item.severity} ({item.security_severity:.1f})"
    return f"{item.level.upper()} · {item.rule_id or 'no rule id'} · {where}{rating} — {item.message}"


def _imported_lines(review: WorkflowReviewReport, *, limit: int) -> list[str]:
    listed = [item for item in review.imported if item.corroborates is None]
    corroborating = len(review.imported) - len(listed)
    if not listed and not corroborating:
        return []
    head = f"Other tools ({_plural(len(listed), 'result')}) — imported SARIF, not verified by Polaris"
    if corroborating:
        head += f"; {corroborating} more corroborate Polaris findings above"
    lines = ["", head + ":"]
    shown = 0
    for tool, items in by_tool(listed):
        if shown >= limit:
            break
        version = items[0].tool_version
        lines.append(f"  {tool}{' ' + version if version else ''} ({len(items)})")
        for item in items[: limit - shown]:
            lines.append("    " + imported_row(item))
            shown += 1
    if len(listed) > shown:
        lines.append(f"  … {len(listed) - shown} more; use --format json or sarif.")
    return lines


def imported_exit_code(report: WorkflowEnvelope, level: str, code: int) -> int:
    """An explicitly requested gate on imported results (`--fail-on-imported LEVEL`).

    1 when an imported result is at or above `level`; 2 when a SARIF input was rejected or
    results went unevaluated past a limit, since then the gate cannot decide. Stale or failed
    reviews and Polaris findings keep their own code.
    """
    if code == 1 or report.status in ("stale", "error"):
        return code
    if any(at_least(item.level, level) for item in report.review.imported):
        return 1
    return 2 if unevaluated(report.review) else code


def import_notes(review: WorkflowReviewReport) -> list[str]:
    """Rejected SARIF inputs, and results of imported ones that were left out (and why)."""
    notes = []
    for record in review.imports:
        if record.status == "rejected":
            notes.append(f"SARIF {record.name}: rejected ({record.error}); nothing was imported from it.")
            continue
        if record.dropped:
            left = ", ".join(f"{count} {reason.replace('_', ' ')}" for reason, count in record.dropped.items())
            notes.append(f"SARIF {record.name}: {record.imported} of {_plural(record.results, 'result')} "
                         f"imported; left out: {left}.")
        if record.failed_runs:
            notes.append(f"SARIF {record.name}: {_plural(record.failed_runs, 'run')} reported no results or an "
                         "unsuccessful execution; that tool may not have finished.")
    return notes


def render_workflow(report: WorkflowEnvelope, *, limit: int = 25) -> str:
    """Human/agent-readable report: what to fix, what to verify, and what was not reviewed."""
    review = report.review
    fix = [finding for finding in review.findings if finding.result == "flagged"]
    verify = [finding for finding in review.findings if finding.result == "needs_context"]
    failed = [finding for finding in review.findings if finding.result == "error"]
    counts: Counter[str] = Counter(finding.severity or "medium" for finding in fix)
    if fix or verify:
        head = _plural(len(fix), "issue") + " to fix"
        if fix:
            head += " (" + ", ".join(f"{counts[name]} {name}" for name in SEVERITIES if counts[name]) + ")"
        head += f" · {len(verify)} to verify"
    else:
        head = "no issues found"
    lines = [f"Polaris security review · {head} · review {report.status}"]
    summary = review.summary
    unreviewed = unreviewed_scope(report)
    scope = [f"{_plural(summary.files_reviewed, 'file')} analyzed"]
    if summary.files_not_applicable:
        scope.append(f"{summary.files_not_applicable} not source code")
    excluded = excluded_count(report)
    if excluded:
        scope.append(f"{excluded} excluded by configuration")
    if unreviewed:
        scope.append(f"{len(unreviewed)} not reviewed")
    context_used = sum(item.used_for_analysis for item in report.context.files)
    detail = ", ".join(scope)
    if context_used:
        detail += f" · {_plural(context_used, 'related file')} followed as context"
    languages = ", ".join(f"{name} {count}" for name, count in sorted(summary.languages.items()) if name != "unsupported")
    if languages:
        detail += f" · {languages}"
    lines.append(f"Scope: {detail} · {summary.elapsed_ms / 1000:.1f}s")
    also = corroborations(review)
    for position, finding in enumerate(fix[:limit], 1):
        lines.append("")
        lines.extend(_finding_block(f"{position}.", finding, also.get(finding.finding_id, ())))
    if len(fix) > limit:
        lines.append("")
        lines.append(f"… {len(fix) - limit} more issue(s) to fix; use --format json, SARIF, or review_details.")
    if verify:
        lines.append("")
        lines.append(f"To verify ({len(verify)}) — possible issues that depend on code or intent Polaris can't see:")
        for position, finding in enumerate(verify[:limit], 1):
            lines.extend(_verify_block(f"  {position}.", finding, also.get(finding.finding_id, ())))
        if len(verify) > limit:
            lines.append(f"  … {len(verify) - limit} more to verify; use --format json or review_details.")
    lines.extend(_imported_lines(review, limit=limit))
    notes = import_notes(review)
    if unreviewed or failed:
        rows = [f"{path} ({REASON_TEXT.get(reason, reason.replace('_', ' '))})" for path, reason in unreviewed[:8]]
        rows.extend(f"{finding.path} ({finding.message})" for finding in failed[:3])
        extra = len(unreviewed) - 8
        notes.append("Not reviewed: " + "; ".join(rows) + (f"; +{extra} more" if extra > 0 else "") + ".")
    for omission in review.coverage.omissions:
        notes.append(f"Limit: {REASON_TEXT.get(omission, omission.replace('_', ' '))}.")
    hidden = []
    if summary.suppressed:
        hidden.append(f"{summary.suppressed} suppressed inline (polaris-ignore)")
    if summary.baselined:
        hidden.append(f"{summary.baselined} in .polaris/baseline.json")
    if hidden:
        notes.append("Hidden: " + ", ".join(hidden) + ".")
    if summary.suppressions_added:
        notes.append(f"{_plural(summary.suppressions_added, 'new polaris-ignore suppression')} added in this change — "
                     "confirm each one is justified.")
    if report.snapshot.omissions:
        examples = ", ".join(f"{item.get('path')} ({item.get('reason')})" for item in report.snapshot.omissions[:3])
        notes.append(f"Freshness: {len(report.snapshot.omissions)} file(s) could not be bound ({examples}); "
                     "re-review after they change.")
    if report.status == "stale":
        notes.append("Stale: files changed while reviewing; run the review again.")
    if not report.changes:
        notes.append("No changed files were selected; pass --files PATH to review existing code.")
    if notes:
        lines.append("")
        lines.extend(notes)
    lines.append("")
    lines.append("Static analysis only: nothing was executed and no model was used. No findings means these "
                 "checks found nothing, not that the code is proven safe.")
    return "\n".join(lines)


class ReportStore:
    """Bounded process-local detail cache; source bodies and secrets are not retained here."""

    def __init__(self, *, capacity: int = 8) -> None:
        if not 1 <= capacity <= 32:
            raise ValueError("invalid report capacity")
        self.capacity = capacity
        self._reports: OrderedDict[str, WorkflowEnvelope] = OrderedDict()
        self._lock = threading.Lock()

    def put(self, report: WorkflowEnvelope) -> None:
        with self._lock:
            self._reports[report.report_id] = report
            self._reports.move_to_end(report.report_id)
            while len(self._reports) > self.capacity:
                self._reports.popitem(last=False)

    def details(self, report_id: str, *, offset: int = 0, limit: int = 25) -> WorkflowDetailPage:
        if not 0 <= offset <= 10_000 or not 1 <= limit <= 50:
            raise ValueError("invalid detail page")
        with self._lock:
            report = self._reports.get(report_id)
        if report is None:
            raise ValueError("report unavailable or evicted; run a fresh review")
        findings = report.review.findings
        end = min(offset + limit, len(findings))
        coverage: dict[str, Any] = report.review.coverage.model_dump(mode="json", exclude={"entries"})
        # Coverage details are independently bounded; no result is hidden as a successful check.
        entries = report.review.coverage.entries
        coverage["entries"] = [item.model_dump(mode="json") for item in entries[offset:offset + limit]]
        coverage["entries_total"] = len(entries)
        coverage["next_offset"] = offset + limit if offset + limit < len(entries) else None
        return WorkflowDetailPage(
            report_id=report.report_id, offset=offset, total_findings=len(findings),
            findings=findings[offset:end], next_offset=end if end < len(findings) else None,
            coverage=coverage, context=report.context, snapshot=report.snapshot,
            notices=[*report.notices, "This is a historical in-memory report. Re-review after any edit."],
        )
