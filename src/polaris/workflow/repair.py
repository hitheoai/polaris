"""Bridge real static-review evidence to bounded host-candidate engineering records.

Neither source text nor candidate JSON may establish policy or fabricate finding references.
CLI application still requires the user's approval of the exact immutable proposal.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

from polaris.engineering import (
    AdditionalFinding,
    FindingReference,
    PatchProposal,
    ReviewContext,
    ReviewedSnapshot,
    StaticReviewObservation,
    capture_supplied_snapshot,
    propose_patch,
    propose_supplied_patch,
)
from polaris.engineering import capture_snapshot as capture_repair_snapshot
from polaris.engineering.errors import EngineeringError
from polaris.engineering.models import EngineeringLimits
from polaris.engineering.service import StaticReviewer
from polaris.integrations._safe import IntegrationProblem
from polaris.integrations.freshness import (
    ReviewSnapshot,
    SnapshotLimits,
    git_bytes,
)
from polaris.jsonio import digest_json
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.capabilities import capability_manifest
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import (
    CapabilityManifest,
    SourceFile,
    TrustedGuardPolicy,
    WorkflowReviewConfig,
)
from polaris.workflow.models import WorkflowEnvelope
from polaris.workflow.requests import CandidateRequest
from polaris.workflow.service import (
    review_policy,
    review_supplied,
    review_workspace,
    scoped_snapshot,
)


def _context(review_digest: str, manifest: CapabilityManifest,
             config: WorkflowReviewConfig, guard_policy: TrustedGuardPolicy | None,
             runtime: AnalysisRuntime) -> ReviewContext:
    return ReviewContext(
        review_digest=review_digest, policy_digest=digest_json(review_policy(config, guard_policy, runtime)),
        analyzer_digest=digest_json([item.model_dump(mode="json") for item in manifest.analyzers]),
        capability_digest=digest_json(manifest.model_dump(mode="json")),
    )


def _references(report: WorkflowEnvelope, candidate: CandidateRequest) -> tuple[FindingReference, ...]:
    available = {item.finding_id: item for item in report.review.findings if item.result == "flagged"}
    refs: dict[str, FindingReference] = {}
    for edit in candidate.edits:
        for finding_id in edit.finding_refs:
            finding = available.get(finding_id)
            if finding is None or finding.path != edit.path:
                raise EngineeringError("scope_mismatch")
            refs[finding_id] = FindingReference(
                finding_id=finding_id, path=finding.path,
                evidence_refs=(f"check:{finding.check_id}", finding.evidence_digest),
            )
    return tuple(refs.values())


def propose_supplied(
    sources: list[SourceFile], candidate: CandidateRequest, *,
    config: WorkflowReviewConfig | None = None, runtime: AnalysisRuntime | None = None,
    guard_policy: TrustedGuardPolicy | None = None,
) -> PatchProposal:
    chosen = config or WorkflowReviewConfig()
    active = runtime or AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
    if len({item.path for item in sources}) != len(sources):
        raise EngineeringError("scope_mismatch")
    report = review_supplied(sources, config=chosen, runtime=active, guard_policy=guard_policy)
    if candidate.expected_snapshot_digest and candidate.expected_snapshot_digest != report.snapshot.digest:
        raise EngineeringError("stale_source")
    selected = {edit.path for edit in candidate.edits}
    contents = {item.path: item.after for item in sources if item.path in selected and item.after is not None}
    related = {item.path: item.after for item in sources if item.path not in selected and item.after is not None}
    if set(contents) != selected:
        raise EngineeringError("scope_mismatch")
    context = _context(report.snapshot.digest, report.review.capabilities, chosen, guard_policy, active)
    snapshot = capture_supplied_snapshot(
        contents, context=context, finding_refs=_references(report, candidate),
        context_sources=related,
    )
    return propose_supplied_patch(
        contents, snapshot, candidate.edits, context=context, rationale=candidate.rationale,
        verification_commands=candidate.verification_commands,
        context_sources=related,
    )


def _file_size(root: Path, path: str) -> int | None:
    try:
        candidate = root / path
        return candidate.stat().st_size if candidate.is_file() and not candidate.is_symlink() else None
    except OSError:
        return None


def _repair_context(root: Path, report: WorkflowEnvelope, paths: list[str]) -> list[str]:
    """Context the approval binds: related analysis context, other reviewed files, then the rest.

    Bounded by the engineering limits so a repair stays reviewable; files beyond the budget
    are not bound (their changes are caught by re-review, not by this approval).
    """
    limits = EngineeringLimits()
    budget = limits.max_total_bytes - sum(_file_size(root, path) or 0 for path in paths)
    ordered = [item.path for item in report.context.files if item.used_for_analysis]
    ordered += [item.path for item in report.changes if item.kind in ("added", "modified", "renamed")]
    ordered += [item.path for item in report.context.files if not item.used_for_analysis]
    chosen: list[str] = []
    for path in dict.fromkeys(ordered):
        if path in paths or len(chosen) >= limits.max_context_files:
            continue
        size = _file_size(root, path)
        if size is None or size > limits.max_file_bytes or size > budget:
            continue
        chosen.append(path)
        budget -= size
    return chosen


def _bound_snapshot(
    root: Path, scope: list[str], config: WorkflowReviewConfig, guard_policy: TrustedGuardPolicy | None,
    runtime: AnalysisRuntime, manifest: CapabilityManifest,
) -> ReviewSnapshot:
    return scoped_snapshot(root, sorted(set(scope)), policy=review_policy(config, guard_policy, runtime),
                           matrix=manifest)


def propose_local(
    root: Path, candidate: CandidateRequest, *, config: WorkflowReviewConfig | None = None,
    runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
) -> PatchProposal:
    chosen = config or WorkflowReviewConfig()
    active = runtime or AnalysisRuntime(allow_external_analyzers=True, allow_temporary_source_files=True)
    report = review_workspace(root, config=chosen, runtime=active, guard_policy=guard_policy)
    if report.status == "stale" or not report.snapshot.complete or report.snapshot.fresh is not True:
        raise EngineeringError("stale_context")
    if candidate.expected_snapshot_digest and candidate.expected_snapshot_digest != report.snapshot.digest:
        raise EngineeringError("stale_source")
    references = _references(report, candidate)
    paths = sorted({edit.path for edit in candidate.edits})
    context_paths = _repair_context(root, report, paths)
    manifest = capability_manifest(runtime=active, probe=True)
    bound = _bound_snapshot(root, [*paths, *context_paths], chosen, guard_policy, active, manifest)
    if not bound.complete:
        raise EngineeringError("stale_context")
    context = _context(bound.digest, manifest, chosen, guard_policy, active)
    snapshot = capture_repair_snapshot(
        root, paths=paths, context=context, finding_refs=references, context_paths=context_paths,
    )
    # The approved files must be exactly the content that was reviewed.
    reviewed = {**{item.path: item.digest for item in report.context.files},
                **{path: digest for path, digest in report.review.provenance.source_digests.items() if digest}}
    for state in (*snapshot.files, *snapshot.context_files):
        if state.path in reviewed and reviewed[state.path] != state.sha256:
            raise EngineeringError("stale_source")
    proposal = propose_patch(
        root, snapshot, candidate.edits, context=context, rationale=candidate.rationale,
        verification_commands=candidate.verification_commands,
    )
    # The bound scope (edited files, their context and project configuration) must still agree.
    if active_context(root, proposal, config=chosen, runtime=runtime, guard_policy=guard_policy) != context:
        raise EngineeringError("stale_context")
    return proposal


def _before_edit_digest(snapshot: ReviewSnapshot, proposal: PatchProposal) -> str:
    """Reconstruct only approved files' pre-edit metadata for a post-edit context check.

    The engineering verifier independently checks that their actual post-edit contents
    equal the approved replacements. Every other source/context/index entry stays current.
    """
    data = snapshot.to_dict()
    original = {item.path: item for item in proposal.snapshot.files}
    edited = {item.path for item in proposal.edits}
    seen = set()
    for item in data["files"]:
        if item["path"] not in edited:
            continue
        before = original[item["path"]]
        if item["kind"] != "file":
            raise EngineeringError("stale_source")
        item.update(digest=before.sha256, size=before.size_bytes, mode=before.mode)
        seen.add(item["path"])
    if seen != edited:
        raise EngineeringError("stale_source")
    # Canonical form of integrations.freshness/0.1.0, tested against the original digest.
    body = {key: data[key] for key in (
        "format", "repository_id", "worktree_id", "head", "index_digest",
        "provenance_digest", "files", "omissions",
    )}
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def active_context(
    root: Path, proposal: PatchProposal, *, config: WorkflowReviewConfig | None = None,
    runtime: AnalysisRuntime | None = None, guard_policy: TrustedGuardPolicy | None = None,
    post_edit: bool = False,
) -> ReviewContext:
    """Recompute actual caller policy/analyzers/context; never trust a proposal's policy claim."""
    chosen = config or WorkflowReviewConfig()
    active = runtime or AnalysisRuntime(allow_external_analyzers=True, allow_temporary_source_files=True)
    manifest = capability_manifest(runtime=active, probe=True)
    scope = [item.path for item in (*proposal.snapshot.files, *proposal.snapshot.context_files)]
    snapshot = _bound_snapshot(root, scope, chosen, guard_policy, active, manifest)
    if not snapshot.complete:
        raise EngineeringError("stale_context")
    review_digest = _before_edit_digest(snapshot, proposal) if post_edit else snapshot.digest
    return _context(review_digest, manifest, chosen, guard_policy, active)


def static_adapter(
    *, config: WorkflowReviewConfig | None = None, runtime: AnalysisRuntime | None = None,
    guard_policy: TrustedGuardPolicy | None = None, root: Path | None = None,
    before_sources: Mapping[str, str] | None = None,
) -> StaticReviewer:
    """Map post-edit findings conservatively to their original path/check references."""
    chosen = config or WorkflowReviewConfig()

    def observe(sources: Mapping[str, str], snapshot: ReviewedSnapshot) -> StaticReviewObservation:
        baselines = dict(before_sources or {})
        if root is not None and guard_policy is not None and snapshot.source_kind == "worktree":
            for path in sources:
                if not any(requirement.path == path for requirement in guard_policy.requirements):
                    continue
                try:
                    raw = git_bytes(
                        root, "show", f"HEAD:{path}", allow_failure=True,
                        limits=SnapshotLimits(max_git_output_bytes=chosen.max_file_bytes),
                    )
                    if raw:
                        baselines[path] = raw.decode("utf-8")
                except (OSError, UnicodeError, IntegrationProblem):
                    pass  # Missing historical evidence must remain incomplete.
        report = WorkflowReviewer(config=chosen, runtime=runtime, guard_policy=guard_policy).review_sources(
            [SourceFile(path, text, baselines.get(path)) for path, text in sources.items()]
        )
        original_checks = {
            (ref.path, evidence.removeprefix("check:"))
            for ref in snapshot.finding_refs for evidence in ref.evidence_refs if evidence.startswith("check:")
        }
        checked = {(item.path, item.check_id) for item in report.coverage.entries if item.status == "checked"}
        required = {(item.path, item.check_id) for item in report.coverage.entries if item.required}
        not_checked = {
            path for path in sources
            if not {pair for pair in original_checks if pair[0] == path}
            or any(pair not in checked for pair in required | original_checks if pair[0] == path)
        }
        if report.coverage.omissions or "*" in not_checked:
            not_checked.update(sources)
        additional = tuple(
            AdditionalFinding.model_validate({
                "finding_id": item.finding_id, "path": item.path,
                "check_id": item.check_id, "result": item.result,
            })
            for item in report.findings
            if item.result != "ok" and (item.path, item.check_id) not in original_checks
        )
        if len(additional) > 128:
            not_checked.update(sources)
        analyzed = tuple(sorted(set(sources) - not_checked))
        outstanding = {(item.path, item.check_id) for item in report.findings if item.result != "ok"}
        remaining = tuple(
            ref.finding_id for ref in snapshot.finding_refs
            if any((ref.path, evidence.removeprefix("check:")) in outstanding
                   for evidence in ref.evidence_refs if evidence.startswith("check:"))
        )
        return StaticReviewObservation(
            status="completed" if report.coverage.complete and not not_checked else "partial",
            review_digest=report.provenance.snapshot_digest,
            analyzed_paths=analyzed, unreviewed_paths=tuple(sorted(set(sources) & not_checked)),
            remaining_finding_refs=remaining,
            additional_findings=additional[:128],
        )

    return observe
