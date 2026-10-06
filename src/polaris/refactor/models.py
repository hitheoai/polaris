"""`polaris.fix-plan/0.1.0`: the fixes Polaris found for the problems it flagged.

A plan holds, for every flagged finding, how each candidate fix fared. A verified fix carries the
bounded proposal that `polaris fix --apply` can write after approval. Proposals contain source and
a diff, so only the file written with `--output` includes them; `plan.summary()` leaves them out.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import Field

from polaris.contract import StrictModel

FIX_PLAN_FORMAT: Literal["polaris.fix-plan/0.1.0"] = "polaris.fix-plan/0.1.0"
Origin = Literal["suggested_edit", "codemod", "ai"]
Short = Annotated[str, Field(min_length=1, max_length=200)]
Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class Attempt(StrictModel):
    """One candidate fix and what happened to it."""

    origin: Origin
    name: Short
    status: Literal["verified", "rejected"]
    reason: Short


class FixItem(StrictModel):
    finding_id: Short
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    line: Annotated[int, Field(ge=1)]
    rule_id: Short
    title: Short
    severity: str | None = None
    # verified: a fix passed every check; rejected: candidates existed but none passed;
    # no_candidate: no generator had a fix; deferred: left for a later run (see `reason`).
    status: Literal["verified", "rejected", "no_candidate", "deferred"]
    reason: Short
    origin: Origin | None = None
    attempts: list[Attempt] = Field(default_factory=list)
    proposal_digest: Digest | None = None
    changed_lines: Annotated[int, Field(ge=0)] = 0
    # The bounded repair proposal (source and diff). None in summaries.
    proposal: dict[str, Any] | None = None
    # Open findings per (path, check) that were already there, so applying the fix can tell them from
    # new ones. In memory only: never written to JSON.
    known: dict[tuple[str, str], int] = Field(default_factory=dict, exclude=True)


class FixCounts(StrictModel):
    flagged: Annotated[int, Field(ge=0)]
    verified: Annotated[int, Field(ge=0)]
    rejected: Annotated[int, Field(ge=0)]
    no_candidate: Annotated[int, Field(ge=0)]
    deferred: Annotated[int, Field(ge=0)]


class FixPlan(StrictModel):
    format: Literal["polaris.fix-plan/0.1.0"] = FIX_PLAN_FORMAT
    # fixes_ready: at least one verified fix; no_fixes: problems exist but none has a verified fix;
    # nothing_to_fix: nothing was flagged.
    status: Literal["fixes_ready", "no_fixes", "nothing_to_fix"]
    review_status: Literal["complete", "incomplete", "stale", "error"]
    scope_label: Annotated[str, Field(min_length=1, max_length=200)]
    counts: FixCounts
    items: list[FixItem]
    notes: list[Annotated[str, Field(min_length=1, max_length=600)]] = Field(default_factory=list)
    behavioral_tests: Literal["not_run"] = "not_run"
    polaris_version: Short

    def summary(self) -> FixPlan:
        """The same plan without proposal bodies (no source, no diffs)."""
        return self.model_copy(update={"items": [item.model_copy(update={"proposal": None}) for item in self.items]})
