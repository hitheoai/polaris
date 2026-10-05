"""The PR preview and the fix preview, offline: what the pull-request bot would post, and whether a
suggested edit survives a static re-review.

Re-verifying an edit re-runs the built-in analyzers in memory on the exact analyzed text (see
`polaris.integrations.forge.verify`); nothing is executed or written. Results are cached per
review and shared by both previews, so toggling plan options verifies only edits it hasn't seen.
The first plan, with default options, is exactly what `polaris pr plan` computes. On-demand fix
verifications are capped at the same limit `pr plan` uses (20 per review run).
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Literal

from polaris.review.models import WorkflowFinding
from polaris.tui.session import ANALYSIS_LOCK, ReviewData

# Local previews are not bound to a forge: these clearly labelled placeholders satisfy the plan
# schema and never appear in the rendered comments or summary.
PLACEHOLDER_REPOSITORY = "local-preview/unpublished"
PLACEHOLDER_PULL_REQUEST = 1
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
IMPORTED_INLINE: tuple[str, ...] = ("none", "security", "errors")
FAIL_ON_IMPORTED: tuple[str | None, ...] = (None, "error", "warning", "note")


@dataclass(frozen=True)
class PlanState:
    """The plan options a reviewer can toggle; the defaults are `pr plan`'s."""

    min_inline_severity: str = "high"
    inline_questions: bool = False
    fail_severity: str = "high"
    inline_imported: str = "none"
    fail_on_imported: str | None = None
    verify_fixes: bool = True

    def options(self) -> Any:
        from polaris.integrations.forge.plan import PlanOptions

        return PlanOptions(
            min_inline_severity=self.min_inline_severity,  # type: ignore[arg-type]
            inline_questions=self.inline_questions, fail_severity=self.fail_severity,  # type: ignore[arg-type]
            inline_imported=self.inline_imported, fail_on_imported=self.fail_on_imported,  # type: ignore[arg-type]
            verify_fixes=self.verify_fixes,
        )

    def toggled(self, option: Literal["inline", "questions", "gate", "imported", "fail_imported", "verify"]
                ) -> PlanState:
        def cycle(values: tuple[Any, ...], current: Any) -> Any:
            return values[(values.index(current) + 1) % len(values)] if current in values else values[0]

        if option == "inline":
            return replace(self, min_inline_severity=cycle(SEVERITIES, self.min_inline_severity))
        if option == "questions":
            return replace(self, inline_questions=not self.inline_questions)
        if option == "gate":
            return replace(self, fail_severity=cycle(SEVERITIES, self.fail_severity))
        if option == "imported":
            return replace(self, inline_imported=cycle(IMPORTED_INLINE, self.inline_imported))
        if option == "fail_imported":
            return replace(self, fail_on_imported=cycle(FAIL_ON_IMPORTED, self.fail_on_imported))
        return replace(self, verify_fixes=not self.verify_fixes)


class Verifier:
    """Per-review cache of suggested-edit verifications, shared by the PR and fix previews."""

    def __init__(self, data: ReviewData) -> None:
        from polaris.integrations.forge.plan import PlanOptions

        self.data = data
        self.results: dict[str, Any] = {}
        self.limit = PlanOptions().max_verifications
        self.on_demand = 0

    @property
    def left(self) -> int:
        return max(0, self.limit - self.on_demand)

    def remember(self, results: dict[str, Any]) -> None:
        for finding_id, result in results.items():
            if result.reason != "verification_limit":
                self.results[finding_id] = result

    def known(self, finding: WorkflowFinding) -> Any:
        return self.results.get(finding.finding_id)

    def verify(self, finding: WorkflowFinding) -> Any:
        """Re-verify one finding's suggested edit (blocking: call it from a worker thread).

        The cache, the budget and the count are read and updated under the analysis lock, so
        concurrent requests never exceed the cap or verify the same edit twice."""
        from polaris.integrations.forge.verify import Verification, verify_edits

        if not self.data.live or finding.suggested_edit is None:
            raise ValueError("verification needs a live review and a suggested edit")
        with ANALYSIS_LOCK:
            cached = self.results.get(finding.finding_id)
            if cached is not None:
                return cached
            if self.left <= 0:
                return Verification("inconclusive", "verification_limit")
            try:
                result = verify_edits(self.data.workspace, [finding], limit=1).get(finding.finding_id)
            except (ValueError, OSError, RuntimeError, RecursionError, MemoryError):
                result = Verification("inconclusive", "verification_failed")
            if result is None:
                result = Verification("not_applicable", "source_unavailable")
            if result.status != "not_applicable":
                self.on_demand += 1
            self.remember({finding.finding_id: result})
            return result

    def plan(self, state: PlanState) -> Any:
        """The review plan for these options (blocking: call it from a worker thread)."""
        from polaris.integrations.forge.plan import build_plan, plan_verifications

        data = self.data
        pull_request = data.pull_request
        if not data.live or pull_request is None:
            raise ValueError("the PR preview needs a live pull-request review")
        options = state.options()
        with ANALYSIS_LOCK:
            verifications = plan_verifications(data.workspace, pull_request.changed, options, known=self.results)
            self.remember(verifications)
            return build_plan(
                data.workspace, repository=PLACEHOLDER_REPOSITORY, pull_request=PLACEHOLDER_PULL_REQUEST,
                base_sha=pull_request.base_sha, head_sha=pull_request.head_sha, merge_base=pull_request.merge_base,
                changed=pull_request.changed, options=options, verifications=verifications,
            )
