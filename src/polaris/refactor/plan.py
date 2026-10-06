"""Turn a workspace review into a plan of verified fixes.

For each flagged finding, in order of severity, the generators propose a whole-file replacement and
the first one that passes every check wins:

1. its change stays near the finding and is small (`gates.scope_problem`);
2. an in-memory re-review reproduces the finding without the fix, then with the fix: the file is
   fully checked, the finding is gone and nothing new appears (`Reverifier`);
3. a bounded, digest-bound proposal can be built for it (size limits, scope, secret guard).

Nothing is written. At most one fix per file is planned per run, because applying one changes the
file the next one was checked against: run `polaris fix` again for the rest.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from polaris import __version__
from polaris.engineering import CandidateEdit, PatchProposal
from polaris.engineering.errors import EngineeringError
from polaris.integrations._safe import IntegrationProblem
from polaris.integrations.forge.verify import MEMORY_ONLY, Reverifier
from polaris.jsonio import digest_text
from polaris.refactor.gates import MAX_CHANGED_LINES, WINDOW, scope_problem
from polaris.refactor.generators import Candidate, Generator
from polaris.refactor.models import Attempt, FixCounts, FixItem, FixPlan
from polaris.review import catalog
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import WorkflowFinding, WorkflowReviewConfig
from polaris.workflow.repair import propose_local
from polaris.workflow.requests import CandidateRequest
from polaris.workflow.service import WorkspaceReview

DEFAULT_LIMIT = 10
MAX_LIMIT = 25


def _rank(finding: WorkflowFinding) -> tuple[int, str, int, str]:
    return (catalog.SEVERITY_ORDER.get(finding.severity or "medium", 2), finding.path, finding.start_line,
            finding.finding_id)


def _item(finding: WorkflowFinding, status: str, reason: str, **fields: object) -> FixItem:
    return FixItem.model_validate({
        "finding_id": finding.finding_id, "path": finding.path, "line": finding.start_line,
        "rule_id": finding.rule_id, "title": finding.title[:200], "severity": finding.severity,
        "status": status, "reason": reason, **fields,
    })


def _attempt(candidate: Candidate, status: Literal["verified", "rejected"], reason: str) -> Attempt:
    return Attempt(origin=candidate.origin, name=candidate.name[:200] or "unnamed", status=status,
                   reason=reason[:200] or "unknown")


def _propose(
    root: Path, review: WorkspaceReview, finding: WorkflowFinding, candidate: Candidate, text: str, *,
    config: WorkflowReviewConfig, runtime: AnalysisRuntime,
) -> PatchProposal:
    """A bounded proposal for the candidate, bound to the same review that found the problem."""
    request = CandidateRequest(
        edits=[CandidateEdit(path=candidate.path, before_sha256=digest_text(text),
                             replacement=candidate.replacement, finding_refs=(finding.finding_id,))],
        rationale=candidate.rationale[:4000] or "A fix for the flagged finding.",
        # A fix never carries commands to run: whatever a generator supplied is dropped.
        verification_commands=[],
    )
    return propose_local(root, request, config=config, runtime=runtime, report=review.envelope)


def build_plan(
    root: Path, review: WorkspaceReview, generators: Sequence[Generator], *,
    config: WorkflowReviewConfig | None = None, runtime: AnalysisRuntime | None = None,
    limit: int = DEFAULT_LIMIT, window: int = WINDOW, max_changed_lines: int = MAX_CHANGED_LINES,
    scope_label: str = "your project",
) -> FixPlan:
    if not 1 <= limit <= MAX_LIMIT:
        raise ValueError("fix limit outside supported bounds")
    chosen = config or WorkflowReviewConfig()
    active = runtime or MEMORY_ONLY
    envelope = review.envelope
    flagged = sorted((item for item in envelope.review.findings if item.result == "flagged"), key=_rank)
    reverifier = Reverifier(review)
    planned: set[str] = set()
    verified = 0
    items: list[FixItem] = []
    for finding in flagged:
        text = reverifier.text_of(finding.path)
        if text is None:
            items.append(_item(finding, "no_candidate", "source_unavailable"))
            continue
        if finding.path in planned:
            items.append(_item(finding, "deferred", "another_fix_to_this_file_comes_first"))
            continue
        if verified >= limit:
            items.append(_item(finding, "deferred", "fix_limit_reached"))
            continue
        attempts: list[Attempt] = []
        winner: FixItem | None = None
        for generator in generators:
            candidate = generator(finding, text)
            if candidate is None:
                continue

            if candidate.path != finding.path:
                attempts.append(_attempt(candidate, "rejected", "edits_another_file"))
                continue
            problem = scope_problem(text, candidate.replacement, finding, window=window,
                                    max_changed_lines=max_changed_lines)
            if problem is not None:
                attempts.append(_attempt(candidate, "rejected", problem))
                continue
            verdict = reverifier.verify(finding, candidate.replacement)
            if verdict.status != "verified":
                attempts.append(_attempt(candidate, "rejected", verdict.reason))
                continue
            try:
                proposal = _propose(root, review, finding, candidate, text, config=chosen, runtime=active)
            except EngineeringError as exc:
                attempts.append(_attempt(candidate, "rejected", exc.code))
                continue
            except (ValueError, OSError, RuntimeError, ValidationError, IntegrationProblem):
                attempts.append(_attempt(candidate, "rejected", "proposal_unavailable"))
                continue
            attempts.append(_attempt(candidate, "verified", verdict.reason))
            winner = _item(
                finding, "verified", verdict.reason, origin=candidate.origin, attempts=attempts,
                proposal_digest=proposal.proposal_digest, changed_lines=proposal.changed_lines,
                proposal=proposal.model_dump(mode="json"),
                known=reverifier.baseline(file.path for file in proposal.snapshot.files),
            )
            break
        if winner is not None:
            planned.add(finding.path)
            verified += 1
            items.append(winner)
        elif attempts:
            items.append(_item(finding, "rejected", attempts[-1].reason, attempts=attempts))
        else:
            items.append(_item(finding, "no_candidate", "no_generator_has_a_fix"))
    counts = FixCounts(
        flagged=len(flagged), verified=verified,
        rejected=sum(item.status == "rejected" for item in items),
        no_candidate=sum(item.status == "no_candidate" for item in items),
        deferred=sum(item.status == "deferred" for item in items),
    )
    notes = []
    if envelope.status != "complete":
        notes.append("Part of the check didn't finish, so there may be problems Polaris couldn't see.")
    if counts.deferred:
        notes.append("Some fixes were left for a later run. Apply the ones shown, then run `polaris fix` again.")
    return FixPlan(
        status="fixes_ready" if verified else "no_fixes" if flagged else "nothing_to_fix",
        review_status=envelope.status, scope_label=scope_label[:200], counts=counts, items=items,
        notes=notes, polaris_version=__version__,
    )
