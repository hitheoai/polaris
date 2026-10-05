"""Public workflow responses; existing review and assessment schemas remain separate."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from polaris.contract import StrictModel
from polaris.review.models import WorkflowFinding, WorkflowReviewReport


class SnapshotReference(StrictModel):
    format: str
    kind: Literal["worktree", "git_index", "git_revision", "submitted_content"]
    digest: str
    repository_id: str | None = None
    worktree_id: str | None = None
    head: str | None = None
    index_digest: str | None = None
    provenance_digest: str | None = None
    complete: bool
    fresh: bool | None = None
    files_count: int
    omissions: list[dict[str, str]] = Field(default_factory=list)
    omitted_scope: list[str] = Field(default_factory=list)


class ChangeRecord(StrictModel):
    path: str
    previous_path: str | None = None
    kind: Literal["added", "modified", "renamed", "deleted", "unreadable", "supplied"]
    before_digest: str | None = None
    after_digest: str | None = None
    changed_lines: int | None = None


RelatedReason = Literal[
    "relative_import", "alias_import", "importer", "tsconfig", "python_import", "test_candidate",
    "project_manifest",
]


class RelatedFile(StrictModel):
    path: str
    digest: str
    bytes: int
    reason: RelatedReason
    # True when the analyzers followed flows through this file (it is not itself reviewed).
    used_for_analysis: bool = False


class ContextSummary(StrictModel):
    files: list[RelatedFile] = Field(default_factory=list)
    omissions: list[str] = Field(default_factory=list)
    bytes_read: int = 0
    scope: str = (
        "Bounded imports, importers, tsconfig and test/manifest candidates. Related source is "
        "analysis context only: flows through it are followed, but it is not reviewed for its own "
        "findings. Context is not policy, proof of whole-program data flow, or evidence that tests ran."
    )


class WorkflowEnvelope(StrictModel):
    format: Literal["polaris.workflow/0.1.0"] = "polaris.workflow/0.1.0"
    report_id: str
    status: Literal["complete", "incomplete", "stale", "error"]
    summary: str
    finding_count: int
    snapshot: SnapshotReference
    changes: list[ChangeRecord]
    context: ContextSummary
    review: WorkflowReviewReport
    tests_status: Literal["not_run"] = "not_run"
    notices: list[str] = Field(default_factory=list)

    def exit_code(self, *, require_complete: bool = False) -> int:
        if self.status in ("stale", "error"):
            return 2
        if self.finding_count:
            return 1
        if require_complete and (
            self.status != "complete"
            or any(finding.result != "ok" for finding in self.review.findings)
        ):
            return 2
        # Runtime/input errors never pass merely because the caller did not choose a strict gate.
        if any(finding.result == "error" for finding in self.review.findings):
            return 2
        return 0


class WorkflowBrief(StrictModel):
    """Default MCP response: bounded findings, counts and an in-memory detail reference."""

    format: Literal["polaris.workflow-summary/0.1.0"] = "polaris.workflow-summary/0.1.0"
    report_id: str
    status: Literal["complete", "incomplete", "stale", "error"]
    summary: str
    finding_count: int
    findings: list[WorkflowFinding]
    findings_remaining: int
    coverage: dict[str, Any]
    snapshot: SnapshotReference
    changed_files: int
    related_files: list[RelatedFile]
    tests_status: Literal["not_run"] = "not_run"
    detail_tool: Literal["review_details"] = "review_details"
    notices: list[str]


class WorkflowDetailPage(StrictModel):
    format: Literal["polaris.workflow-details/0.1.0"] = "polaris.workflow-details/0.1.0"
    report_id: str
    offset: Annotated[int, Field(ge=0)]
    total_findings: int
    findings: list[WorkflowFinding]
    next_offset: int | None
    coverage: dict[str, Any]
    context: ContextSummary
    snapshot: SnapshotReference
    notices: list[str]
