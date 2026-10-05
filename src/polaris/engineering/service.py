"""Bound host candidates without executing code, inferring policy, or loading a model."""

from __future__ import annotations

import difflib
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Protocol

from polaris.engineering.errors import EngineeringError
from polaris.engineering.models import (
    CandidateEdit,
    EngineeringLimits,
    FileState,
    FindingReference,
    FindingVerification,
    InputValue,
    PatchProposal,
    ProcessAction,
    ProposalValidation,
    ReviewContext,
    ReviewedSnapshot,
    StaticReviewObservation,
    VerificationRecord,
    parse_model,
    parse_proposal,
    parse_snapshot,
)
from polaris.engineering.security import guard_output, relative_path, utf8_bytes
from polaris.engineering.workspace import ReadSource, Workspace
from polaris.jsonio import digest_bytes, digest_json


class StaticReviewer(Protocol):
    """Only an application-configured, non-executing static analyzer belongs here."""

    def __call__(
        self, sources: Mapping[str, str], snapshot: ReviewedSnapshot
    ) -> StaticReviewObservation: ...


def limits_or_default(limits: EngineeringLimits | None) -> EngineeringLimits:
    return parse_model(EngineeringLimits, limits or EngineeringLimits())


def _paths(paths: Sequence[str], *, limit: int, nonempty: bool = False) -> tuple[str, ...]:
    if isinstance(paths, (str, bytes)) or len(paths) > limit or (nonempty and not paths):
        raise EngineeringError("source_limit")
    result = tuple(relative_path(path) for path in paths)
    if len(result) != len(set(result)):
        raise EngineeringError("scope_mismatch")
    return tuple(sorted(result))


def _supplied_states(
    sources: Mapping[str, str],
    context_sources: Mapping[str, str],
    limits: EngineeringLimits,
) -> tuple[tuple[FileState, ...], tuple[FileState, ...]]:
    paths = _paths(tuple(sources), limit=limits.max_files, nonempty=True)
    context_paths = _paths(tuple(context_sources), limit=limits.max_context_files)
    if set(paths) & set(context_paths):
        raise EngineeringError("scope_mismatch")
    size = 0
    groups: list[tuple[FileState, ...]] = []
    for mapping, selected in ((sources, paths), (context_sources, context_paths)):
        states = []
        for path in selected:
            raw = utf8_bytes(mapping[path])
            size += len(raw)
            if len(raw) > limits.max_file_bytes or size > limits.max_total_bytes:
                raise EngineeringError("source_limit")
            states.append(FileState(path=path, sha256=digest_bytes(raw), size_bytes=len(raw)))
        groups.append(tuple(states))
    return groups[0], groups[1]


def read_workspace(
    workspace: Workspace,
    paths: Sequence[str],
    context_paths: Sequence[str],
    limits: EngineeringLimits,
) -> tuple[dict[str, ReadSource], dict[str, ReadSource]]:
    paths = _paths(paths, limit=limits.max_files, nonempty=True)
    context_paths = _paths(context_paths, limit=limits.max_context_files)
    if set(paths) & set(context_paths):
        raise EngineeringError("scope_mismatch")
    size = 0
    seen: set[tuple[int, ...]] = set()
    groups: list[dict[str, ReadSource]] = []
    for selected in (paths, context_paths):
        sources: dict[str, ReadSource] = {}
        for path in selected:
            item = workspace.read(path)
            size += item.state.size_bytes
            if size > limits.max_total_bytes:
                raise EngineeringError("source_limit")
            # Detect case-insensitive/Unicode-normalization aliases as well as hard links.
            identity = item.fingerprint[:2]
            if identity in seen:
                raise EngineeringError("scope_mismatch")
            seen.add(identity)
            sources[path] = item
        groups.append(sources)
    for group in groups:
        for path, item in group.items():
            if workspace.read(path).fingerprint != item.fingerprint:
                raise EngineeringError("race_detected")
    workspace.assert_root()
    return groups[0], groups[1]


def _snapshot(
    *,
    source_kind: Literal["worktree", "submitted_content"],
    root_digest: str | None,
    files: tuple[FileState, ...],
    context_files: tuple[FileState, ...],
    context: ReviewContext,
    finding_refs: Sequence[FindingReference],
) -> ReviewedSnapshot:
    if not 1 <= len(finding_refs) <= 128:
        raise EngineeringError("source_limit")
    refs = tuple(
        sorted(
            (parse_model(FindingReference, ref) for ref in finding_refs),
            key=lambda ref: ref.finding_id,
        )
    )
    context = parse_model(ReviewContext, context)
    data = {
        "format": "polaris.repair-snapshot/0.1.0",
        "source_kind": source_kind,
        "root_digest": root_digest,
        "files": [item.model_dump(mode="json") for item in files],
        "context_files": [item.model_dump(mode="json") for item in context_files],
        "context": context.model_dump(mode="json"),
        "finding_refs": [item.model_dump(mode="json") for item in refs],
    }
    guard_output(data)
    return parse_snapshot({**data, "snapshot_digest": digest_json(data)})


def capture_supplied_snapshot(
    sources: Mapping[str, str],
    *,
    context: ReviewContext,
    finding_refs: Sequence[FindingReference],
    context_sources: Mapping[str, str] | None = None,
    limits: EngineeringLimits | None = None,
) -> ReviewedSnapshot:
    """Hash bounded supplied content only. Never resolve/read a server-side path."""
    bounds = limits_or_default(limits)
    files, context_files = _supplied_states(sources, context_sources or {}, bounds)
    return _snapshot(
        source_kind="submitted_content",
        root_digest=None,
        files=files,
        context_files=context_files,
        context=context,
        finding_refs=finding_refs,
    )


def capture_snapshot(
    root: Path,
    *,
    paths: Sequence[str],
    context: ReviewContext,
    finding_refs: Sequence[FindingReference],
    context_paths: Sequence[str] = (),
    limits: EngineeringLimits | None = None,
) -> ReviewedSnapshot:
    """Hash caller-selected existing files; policy and findings must come from the caller."""
    bounds = limits_or_default(limits)
    with Workspace(root, max_file_bytes=bounds.max_file_bytes) as workspace:
        sources, contexts = read_workspace(workspace, paths, context_paths, bounds)
        return _snapshot(
            source_kind="worktree",
            root_digest=workspace.root_digest,
            files=tuple(item.state for item in sources.values()),
            context_files=tuple(item.state for item in contexts.values()),
            context=context,
            finding_refs=finding_refs,
        )


def compare_snapshot(
    snapshot: ReviewedSnapshot,
    *,
    source_kind: Literal["worktree", "submitted_content"],
    root_digest: str | None,
    files: tuple[FileState, ...],
    context_files: tuple[FileState, ...],
    context: ReviewContext,
    replacements: Mapping[str, str] | None = None,
) -> None:
    if snapshot.source_kind != source_kind or snapshot.root_digest != root_digest:
        raise EngineeringError("snapshot_mismatch")
    if snapshot.context != parse_model(ReviewContext, context) or snapshot.context_files != context_files:
        raise EngineeringError("stale_context")
    expected = []
    for state in snapshot.files:
        if replacements is not None and state.path in replacements:
            raw = utf8_bytes(replacements[state.path])
            expected.append(
                FileState(path=state.path, sha256=digest_bytes(raw), size_bytes=len(raw), mode=state.mode)
            )
        else:
            expected.append(state)
    if tuple(expected) != files:
        raise EngineeringError("stale_source")


def check_workspace(
    workspace: Workspace,
    snapshot: ReviewedSnapshot,
    *,
    context: ReviewContext,
    limits: EngineeringLimits,
    replacements: Mapping[str, str] | None = None,
) -> tuple[dict[str, ReadSource], dict[str, ReadSource]]:
    sources, contexts = read_workspace(
        workspace,
        tuple(state.path for state in snapshot.files),
        tuple(state.path for state in snapshot.context_files),
        limits,
    )
    compare_snapshot(
        snapshot,
        source_kind="worktree",
        root_digest=workspace.root_digest,
        files=tuple(item.state for item in sources.values()),
        context_files=tuple(item.state for item in contexts.values()),
        context=context,
        replacements=replacements,
    )
    return sources, contexts


def _diff(
    sources: Mapping[str, str], edits: tuple[CandidateEdit, ...], limits: EngineeringLimits
) -> tuple[str, int]:
    chunks: list[str] = []
    size = changed_lines = 0
    for edit in edits:
        before = sources[edit.path]
        after = edit.replacement
        if before == after:
            raise EngineeringError("no_change")
        # A removed secret would still be exposed in the reviewable diff. Fail closed.
        guard_output((before, after))
        before_lines, after_lines = before.splitlines(keepends=True), after.splitlines(keepends=True)
        matcher = difflib.SequenceMatcher(a=before_lines, b=after_lines)
        changed_lines += sum(
            old_end - old_start + new_end - new_start
            for tag, old_start, old_end, new_start, new_end in matcher.get_opcodes()
            if tag != "equal"
        )
        if changed_lines > limits.max_changed_lines:
            raise EngineeringError("patch_limit")
        for chunk in difflib.unified_diff(
            before_lines, after_lines, fromfile=f"a/{edit.path}", tofile=f"b/{edit.path}", n=3
        ):
            if not chunk.endswith("\n"):
                chunk += "\n\\ No newline at end of file\n"
            size += len(utf8_bytes(chunk))
            if size > limits.max_patch_bytes:
                raise EngineeringError("patch_limit")
            chunks.append(chunk)
    return "".join(chunks), changed_lines


def build_proposal(
    sources: Mapping[str, str],
    snapshot: ReviewedSnapshot,
    edits: Sequence[CandidateEdit],
    *,
    rationale: str,
    verification_commands: Sequence[ProcessAction],
    limits: EngineeringLimits,
    origin: Literal["host_candidate", "configured_generator"] = "host_candidate",
) -> PatchProposal:
    if not 1 <= len(edits) <= limits.max_edits or len(verification_commands) > 16:
        raise EngineeringError("patch_limit")
    candidates = tuple(
        sorted((parse_model(CandidateEdit, edit) for edit in edits), key=lambda edit: edit.path)
    )
    if len({edit.path for edit in candidates}) != len(candidates):
        raise EngineeringError("scope_mismatch")
    states = {state.path: state for state in snapshot.files}
    findings = {ref.finding_id: ref.path for ref in snapshot.finding_refs}
    total_after = sum(state.size_bytes for state in (*snapshot.files, *snapshot.context_files))
    for edit in candidates:
        relative_path(edit.path)
        if edit.path not in states or any(findings.get(ref) != edit.path for ref in edit.finding_refs):
            raise EngineeringError("scope_mismatch")
        if edit.before_sha256 != states[edit.path].sha256:
            raise EngineeringError("stale_source")
        size = len(utf8_bytes(edit.replacement))
        if size > limits.max_file_bytes:
            raise EngineeringError("source_limit")
        total_after += size - states[edit.path].size_bytes
    if total_after > limits.max_total_bytes:
        raise EngineeringError("source_limit")
    commands = tuple(parse_model(ProcessAction, command) for command in verification_commands)
    diff, changed_lines = _diff(sources, candidates, limits)
    data: dict[str, Any] = {
        "format": "polaris.proposal/0.1.0",
        "snapshot": snapshot.model_dump(mode="json"),
        "origin": origin,
        "edits": [edit.model_dump(mode="json") for edit in candidates],
        "rationale": rationale,
        "verification_commands": [command.model_dump(mode="json") for command in commands],
        "diff": diff,
        "changed_lines": changed_lines,
    }
    guard_output(data)
    return parse_proposal({**data, "proposal_digest": digest_json(data)})


def propose_supplied_patch(
    sources: Mapping[str, str],
    snapshot: ReviewedSnapshot,
    edits: Sequence[CandidateEdit],
    *,
    context: ReviewContext,
    rationale: str,
    verification_commands: Sequence[ProcessAction] = (),
    context_sources: Mapping[str, str] | None = None,
    limits: EngineeringLimits | None = None,
) -> PatchProposal:
    bounds = limits_or_default(limits)
    snapshot = parse_snapshot(snapshot)
    files, context_files = _supplied_states(sources, context_sources or {}, bounds)
    compare_snapshot(
        snapshot, source_kind="submitted_content", root_digest=None, files=files,
        context_files=context_files, context=context,
    )
    return build_proposal(
        sources, snapshot, edits, rationale=rationale,
        verification_commands=verification_commands, limits=bounds,
    )


def propose_patch(
    root: Path,
    snapshot: ReviewedSnapshot,
    edits: Sequence[CandidateEdit],
    *,
    context: ReviewContext,
    rationale: str,
    verification_commands: Sequence[ProcessAction] = (),
    limits: EngineeringLimits | None = None,
) -> PatchProposal:
    bounds = limits_or_default(limits)
    snapshot = parse_snapshot(snapshot)
    with Workspace(root, max_file_bytes=bounds.max_file_bytes) as workspace:
        sources, _ = check_workspace(workspace, snapshot, context=context, limits=bounds)
        proposal = build_proposal(
            {path: item.text for path, item in sources.items()}, snapshot, edits,
            rationale=rationale, verification_commands=verification_commands, limits=bounds,
        )
        check_workspace(workspace, snapshot, context=context, limits=bounds)
        return proposal


def require_digest(proposal: PatchProposal, expected_proposal_digest: str) -> None:
    if proposal.proposal_digest != expected_proposal_digest:
        raise EngineeringError("proposal_mismatch")


def validate_derived_diff(
    sources: Mapping[str, str], proposal: PatchProposal, limits: EngineeringLimits
) -> ProposalValidation:
    derived = build_proposal(
        sources, proposal.snapshot, proposal.edits, rationale=proposal.rationale,
        verification_commands=proposal.verification_commands, limits=limits, origin=proposal.origin,
    )
    if derived != proposal:
        raise EngineeringError("proposal_mismatch")
    return ProposalValidation(
        proposal_digest=proposal.proposal_digest,
        snapshot_digest=proposal.snapshot.snapshot_digest,
        paths=tuple(edit.path for edit in proposal.edits),
    )


def validate_supplied_proposal(
    sources: Mapping[str, str],
    proposal: InputValue,
    *,
    expected_proposal_digest: str,
    context: ReviewContext,
    context_sources: Mapping[str, str] | None = None,
    limits: EngineeringLimits | None = None,
) -> ProposalValidation:
    bounds = limits_or_default(limits)
    proposal = parse_proposal(proposal)
    require_digest(proposal, expected_proposal_digest)
    files, context_files = _supplied_states(sources, context_sources or {}, bounds)
    compare_snapshot(
        proposal.snapshot, source_kind="submitted_content", root_digest=None, files=files,
        context_files=context_files, context=context,
    )
    return validate_derived_diff(sources, proposal, bounds)


def validate_proposal(
    root: Path,
    proposal: InputValue,
    *,
    expected_proposal_digest: str,
    context: ReviewContext,
    limits: EngineeringLimits | None = None,
) -> ProposalValidation:
    bounds = limits_or_default(limits)
    proposal = parse_proposal(proposal)
    require_digest(proposal, expected_proposal_digest)
    with Workspace(root, max_file_bytes=bounds.max_file_bytes) as workspace:
        sources, _ = check_workspace(workspace, proposal.snapshot, context=context, limits=bounds)
        result = validate_derived_diff(
            {path: item.text for path, item in sources.items()}, proposal, bounds
        )
        check_workspace(workspace, proposal.snapshot, context=context, limits=bounds)
        return result


def _observe(
    sources: Mapping[str, str],
    snapshot: ReviewedSnapshot,
    static_reviewer: StaticReviewer | None,
) -> StaticReviewObservation:
    paths = tuple(state.path for state in snapshot.files)
    if static_reviewer is None:
        return StaticReviewObservation(status="unavailable", unreviewed_paths=paths)
    try:
        observed = parse_model(
            StaticReviewObservation, static_reviewer(MappingProxyType(dict(sources)), snapshot)
        )
        guard_output(observed)
        original_ids = {ref.finding_id for ref in snapshot.finding_refs}
        if (
            set(observed.analyzed_paths) | set(observed.unreviewed_paths) != set(paths)
            or not set(observed.remaining_finding_refs) <= original_ids
            or any(
                item.path not in paths or item.finding_id in original_ids
                for item in observed.additional_findings
            )
            or (observed.status == "completed" and observed.unreviewed_paths)
            or (
                observed.status in ("unavailable", "error")
                and (observed.analyzed_paths or observed.remaining_finding_refs or observed.additional_findings)
            )
        ):
            raise EngineeringError("review_failed")
        return observed
    except Exception:
        # Static adapter errors can contain repository content. Do not echo them.
        return StaticReviewObservation(status="error", unreviewed_paths=paths)


def _verification(
    proposal: PatchProposal, files: tuple[FileState, ...], observed: StaticReviewObservation
) -> VerificationRecord:
    findings = tuple(
        FindingVerification(
            finding_id=ref.finding_id,
            status=(
                "not_reviewed"
                if observed.status not in ("completed", "partial") or ref.path not in observed.analyzed_paths
                else "still_detected"
                if ref.finding_id in observed.remaining_finding_refs
                else "no_longer_detected"
            ),
        )
        for ref in proposal.snapshot.finding_refs
    )
    return VerificationRecord(
        proposal_digest=proposal.proposal_digest,
        snapshot_digest=proposal.snapshot.snapshot_digest,
        status="error" if observed.status == "error" else "verified_snapshot",
        observed_files=files, static_review=observed, findings=findings,
        error_code="review_failed" if observed.status == "error" else None,
    )


def _failed_verification(proposal: PatchProposal, exc: EngineeringError) -> VerificationRecord:
    return VerificationRecord(
        proposal_digest=proposal.proposal_digest,
        snapshot_digest=proposal.snapshot.snapshot_digest,
        status="stale" if exc.code in ("stale_source", "stale_context", "race_detected") else "error",
        static_review=StaticReviewObservation(
            status="unavailable", unreviewed_paths=tuple(item.path for item in proposal.snapshot.files)
        ),
        findings=tuple(
            FindingVerification(finding_id=ref.finding_id, status="not_reviewed")
            for ref in proposal.snapshot.finding_refs
        ),
        error_code=exc.code,
    )


def verify_supplied_proposal(
    sources: Mapping[str, str],
    proposal: InputValue,
    *,
    expected_proposal_digest: str,
    context: ReviewContext,
    context_sources: Mapping[str, str] | None = None,
    static_reviewer: StaticReviewer | None = None,
    limits: EngineeringLimits | None = None,
) -> VerificationRecord:
    """Observe supplied post-edit content; never claim it is the caller's actual filesystem."""
    proposal = parse_proposal(proposal)
    require_digest(proposal, expected_proposal_digest)
    bounds = limits_or_default(limits)
    try:
        guard_output(proposal)
        files, context_files = _supplied_states(sources, context_sources or {}, bounds)
        compare_snapshot(
            proposal.snapshot, source_kind="submitted_content", root_digest=None, files=files,
            context_files=context_files, context=context,
            replacements={edit.path: edit.replacement for edit in proposal.edits},
        )
        observed = _observe(sources, proposal.snapshot, static_reviewer)
        if _supplied_states(sources, context_sources or {}, bounds) != (files, context_files):
            raise EngineeringError("stale_source")
        return _verification(proposal, files, observed)
    except EngineeringError as exc:
        return _failed_verification(proposal, exc)


def verify_proposal(
    root: Path,
    proposal: InputValue,
    *,
    expected_proposal_digest: str,
    context: ReviewContext,
    static_reviewer: StaticReviewer | None = None,
    limits: EngineeringLimits | None = None,
) -> VerificationRecord:
    """Rehash the post-edit worktree and invoke only an explicitly supplied static adapter."""
    proposal = parse_proposal(proposal)
    require_digest(proposal, expected_proposal_digest)
    bounds = limits_or_default(limits)
    try:
        guard_output(proposal)
        with Workspace(root, max_file_bytes=bounds.max_file_bytes) as workspace:
            replacements = {edit.path: edit.replacement for edit in proposal.edits}
            sources, _ = check_workspace(
                workspace, proposal.snapshot, context=context, limits=bounds, replacements=replacements
            )
            observed = _observe(
                {path: item.text for path, item in sources.items()}, proposal.snapshot, static_reviewer
            )
            check_workspace(
                workspace, proposal.snapshot, context=context, limits=bounds, replacements=replacements
            )
            return _verification(proposal, tuple(item.state for item in sources.values()), observed)
    except EngineeringError as exc:
        return _failed_verification(proposal, exc)
