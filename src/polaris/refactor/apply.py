"""Write one verified fix, then check the result, with the engineering pipeline Polaris already has.

The caller is responsible for the human decision: `apply_fix` must only be called after a person
approved this exact proposal (its digest). It recomputes the approval context from the worktree as
it is now, so a file or setting that changed since the plan makes the application fail rather than
write over someone else's work. It never runs project code or tests.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from polaris.engineering import (
    ProposalApproval,
    apply_proposal,
    parse_proposal,
    verify_proposal,
)
from polaris.engineering.errors import EngineeringError
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import WorkflowReviewConfig
from polaris.workflow.repair import active_context, static_adapter

APPROVAL_SECONDS = 60


@dataclass(frozen=True)
class ApplyOutcome:
    # applied: the file was written; verified: a fresh static re-review confirms the finding is
    # gone, everything required was checked and nothing new appeared.
    applied: bool
    verified: bool
    reason: str


def apply_fix(
    root: Path, proposal_data: dict[str, Any], *, approved_digest: str,
    config: WorkflowReviewConfig, runtime: AnalysisRuntime,
    known: Mapping[tuple[str, str], int] | None = None,
) -> ApplyOutcome:
    # `known`: open findings per (path, check) from before the fix. Findings already there are not
    # held against it; without it any open finding on another check makes the result unconfirmed.
    allowed = known or {}
    try:
        proposal = parse_proposal(proposal_data)
        if approved_digest != proposal.proposal_digest:
            return ApplyOutcome(False, False, "proposal_mismatch")
        context = active_context(root, proposal, config=config, runtime=runtime)
        now = int(time.time())
        approval = ProposalApproval(
            proposal_digest=proposal.proposal_digest, snapshot_digest=proposal.snapshot.snapshot_digest,
            approved=True, approved_at_unix=now, expires_at_unix=now + APPROVAL_SECONDS,
        )
        receipt = apply_proposal(root, proposal, approval=approval, context=context)
        if receipt.status != "applied":
            return ApplyOutcome(receipt.status == "partially_applied", False, receipt.error_code or "not_applied")
        after = active_context(root, proposal, config=config, runtime=runtime, post_edit=True)
        verification = verify_proposal(
            root, proposal, expected_proposal_digest=proposal.proposal_digest, context=after,
            static_reviewer=static_adapter(config=config, runtime=runtime, root=root),
        )
        if active_context(root, proposal, config=config, runtime=runtime, post_edit=True) != after:
            return ApplyOutcome(True, False, "changed_during_verification")
        extra = Counter((item.path, item.check_id) for item in verification.static_review.additional_findings)
        confirmed = (
            verification.status == "verified_snapshot"
            and verification.static_review.status == "completed"
            and all(count <= allowed.get(key, 0) for key, count in extra.items())
            and all(item.status == "no_longer_detected" for item in verification.findings)
        )
        return ApplyOutcome(True, confirmed, "no_longer_detected" if confirmed else "not_confirmed")
    except EngineeringError as exc:
        return ApplyOutcome(False, False, exc.code)
