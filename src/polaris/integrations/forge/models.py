"""Versioned pull-request review plan: produced offline, validated again before publishing."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from polaris.contract import StrictModel
from polaris.integrations.forge.markdown import FINDING_KEY, MARKER_OPEN, imported_tag
from polaris.review.models import valid_source_path

PLAN_FORMAT: Literal["polaris.pr-plan/0.1.0"] = "polaris.pr-plan/0.1.0"
RECEIPT_FORMAT: Literal["polaris.pr-publish/0.1.0"] = "polaris.pr-publish/0.1.0"
MAX_COMMENTS = 100
MAX_COMMENT_CHARS = 16_000
MAX_SUMMARY_CHARS = 60_000
MAX_KEYS = 10_000
MAX_PLAN_BYTES = 4_000_000

Sha = Annotated[str, Field(pattern=r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")]
Repository = Annotated[str, Field(max_length=140, pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$")]
PullNumber = Annotated[int, Field(ge=1, le=2_147_483_647)]
# A Polaris finding's fingerprint, or "sarif-<tool tag>-<fingerprint>" for an imported result.
FindingKey = Annotated[str, Field(pattern=rf"^(?:{FINDING_KEY})$")]
ToolTag = Annotated[str, Field(pattern=r"^[0-9a-f]{8}$")]
PlanPath = Annotated[str, Field(min_length=1, max_length=1024)]
Count = Annotated[int, Field(ge=0)]
Severity = Literal["critical", "high", "medium", "low", "info"]
Gate = Literal["pass", "fail", "incomplete"]


class PlannedComment(StrictModel):
    """One inline comment, anchored to a line the pull request changed (right side of the diff).

    `origin="imported"` comments carry another tool's result from an imported SARIF file
    (opt-in); their keys use the imported grammar and Polaris did not verify them.
    """

    key: FindingKey
    finding_id: Annotated[str, Field(pattern=r"^[0-9a-f]{8,64}$")]
    path: PlanPath
    line: Annotated[int, Field(ge=1, le=10_000_000)]
    severity: Severity
    result: Literal["flagged", "needs_context"]
    rule_id: Annotated[str, Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_.:/@-]+$")]
    title: Annotated[str, Field(min_length=1, max_length=200)]
    body: Annotated[str, Field(min_length=1, max_length=MAX_COMMENT_CHARS)]
    suggestion: Literal["verified", "withheld", "none"] = "none"
    origin: Literal["polaris", "imported"] = "polaris"

    @model_validator(mode="after")
    def inert(self) -> Self:
        if not valid_source_path(self.path):
            raise ValueError("comment path must be a relative repository path")
        if MARKER_OPEN in self.body or MARKER_OPEN in self.title:
            raise ValueError("comment text must not contain Polaris state markers")
        if (self.origin == "imported") != (imported_tag(self.key) is not None):
            raise ValueError("imported comments, and only they, use imported keys")
        if self.origin == "imported" and (self.suggestion != "none" or self.result != "flagged"):
            raise ValueError("imported comments offer no suggestion")
        return self


class PlanCounts(StrictModel):
    issues_in_change: Count
    questions_in_change: Count
    lower_severity_in_change: Count
    existing_in_changed_files: Count
    inline: Count
    not_reviewed_files: Count
    suggestions_verified: Count
    suggestions_withheld: Count
    # Results imported from other tools' SARIF on changed lines, how many are commented inline
    # (opt-in), and SARIF inputs that were rejected.
    imported_in_change: Count = 0
    imported_inline: Count = 0
    imports_rejected: Count = 0


class ReviewPlan(StrictModel):
    """Everything `publish` may write, bound to one repository, pull request and head commit."""

    format: Literal["polaris.pr-plan/0.1.0"] = PLAN_FORMAT
    polaris_version: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9.+_-]+$")]
    repository: Repository
    pull_request: PullNumber
    base_sha: Sha
    head_sha: Sha
    merge_base: Sha
    report_id: Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
    review_status: Literal["complete", "incomplete", "stale", "error"]
    gate: Gate
    counts: PlanCounts
    comments: Annotated[list[PlannedComment], Field(max_length=MAX_COMMENTS)]
    # Every finding Polaris still detects in the reviewed files: earlier comments for these
    # findings are never marked resolved, even when they are no longer commented inline.
    detected_keys: Annotated[list[FindingKey], Field(max_length=MAX_KEYS)]
    # Files whose required checks all completed; only their findings can be declared gone.
    checked_paths: Annotated[list[PlanPath], Field(max_length=MAX_KEYS)]
    summary: Annotated[str, Field(min_length=1, max_length=MAX_SUMMARY_CHARS)]
    # Tags of tools whose SARIF this run imported completely (none was rejected or cut at a
    # limit), and the reviewed paths it covered: only an earlier imported comment of a listed
    # tool on a listed path can be declared gone. Empty when nothing was imported.
    imported_tools: Annotated[list[ToolTag], Field(max_length=256)] = Field(default_factory=list)
    imported_paths: Annotated[list[PlanPath], Field(max_length=MAX_KEYS)] = Field(default_factory=list)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        keys = [comment.key for comment in self.comments]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate comment key")
        if not set(keys) <= set(self.detected_keys):
            raise ValueError("every comment must belong to a detected finding")
        if MARKER_OPEN in self.summary:
            raise ValueError("summary must not contain Polaris state markers")
        if not all(valid_source_path(path) for path in (*self.checked_paths, *self.imported_paths)):
            raise ValueError("checked paths must be relative repository paths")
        if self.counts.inline != len(self.comments):
            raise ValueError("inline count must match the planned comments")
        if self.counts.imported_inline != sum(comment.origin == "imported" for comment in self.comments):
            raise ValueError("imported inline count must match the planned comments")
        if bool(self.imported_tools) and not self.imported_paths:
            raise ValueError("imported tools need the paths their results covered")
        return self


class PublishReceipt(StrictModel):
    """What publishing did; contains counts only, never source, comment bodies or credentials."""

    format: Literal["polaris.pr-publish/0.1.0"] = RECEIPT_FORMAT
    status: Literal["published", "dry_run", "stale_head", "not_open"]
    repository: Repository
    pull_request: PullNumber
    head_sha: Sha
    gate: Gate
    posted: Count = 0
    already_posted: Count = 0
    moved_to_summary: Count = 0
    resolved: Count = 0
    thread_resolution_errors: Count = 0
    summary: Literal["created", "updated", "unchanged", "not_written"] = "not_written"
