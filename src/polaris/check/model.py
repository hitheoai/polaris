"""`polaris.check/1`: one security check result, in plain words, for people and their AI agents.

The simple terminal view, `polaris check` (text, Markdown and `--json`), the MCP tools and the
agent hooks all show this model. It is built from a full Polaris review (`build.build_check`),
bounded in size and deterministic: the same review always gives the same result. Plain text
comes from the Polaris catalog; anything derived from the repository (file names, function names,
code labels) is validated and length-bounded data, never instructions.
"""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from polaris.contract import StrictModel
from polaris.review.models import Confidence, Severity, valid_source_path

CHECK_FORMAT: Literal["polaris.check/1"] = "polaris.check/1"
# Full detail for at most this many items; the rest are counted in `more`.
MAX_ITEMS = 50
Priority = Literal["fix_now", "check_this", "worth_a_look"]
PRIORITIES: tuple[Priority, ...] = ("fix_now", "check_this", "worth_a_look")
Status = Literal["clear", "fix_needed", "incomplete"]
Scope = Literal["changes", "project", "staged", "range", "files", "pull_request", "folder"]

Short = Annotated[str, Field(min_length=1, max_length=200)]
Text = Annotated[str, Field(min_length=1, max_length=600)]
ItemId = Annotated[str, Field(pattern=r"^[0-9a-f]{8,64}$")]
FilePath = Annotated[str, Field(min_length=1, max_length=1024)]
Line = Annotated[int, Field(ge=1)]
Count = Annotated[int, Field(ge=0)]


class Where(StrictModel):
    """Where the problem is. `route` names the page or API route when Polaris knows it."""

    file: FilePath
    line: Line
    end_line: Line
    function: Short | None = None
    route: Short | None = None

    @model_validator(mode="after")
    def located(self) -> Self:
        if not valid_source_path(self.file) or self.end_line < self.line:
            raise ValueError("a location needs a relative file path and a line range")
        return self


class Step(StrictModel):
    """One step of how outside data reaches the problem line (labels are short code fragments)."""

    kind: Literal["source", "step", "call", "sink"]
    file: FilePath
    line: Line
    label: Short


class SuggestedFix(StrictModel):
    """A one-line edit Polaris generated. `verified`: a fresh check with the edit applied no
    longer finds the problem and finds nothing new; `withheld`: that re-check failed or couldn't
    decide; `not_checked`: no re-check was run (for example, a saved report)."""

    line: Line
    before: Annotated[str, Field(max_length=2_000)]
    after: Annotated[str, Field(max_length=2_000)]
    status: Literal["verified", "withheld", "not_checked"]
    note: Annotated[str, Field(max_length=300)] = ""


class Fix(StrictModel):
    instruction: Text  # plain words, from the catalog
    detail: Annotated[str, Field(max_length=1_200)] | None = None  # the rule's technical guidance
    edit: SuggestedFix | None = None


class Technical(StrictModel):
    """The same problem for developers and agents: the exact check, rule and evidence."""

    check: Short
    rule: Short
    title: Short
    severity: Severity
    confidence: Confidence | None = None
    cwe: Short | None = None
    message: Annotated[str, Field(max_length=600)]
    verify: Annotated[str, Field(max_length=1_000)] | None = None
    finding_id: Short


class CheckItem(StrictModel):
    """One problem: what's wrong (`title`), why it matters, where, how to fix, and a prompt to
    hand to an AI. `question` is set for "check this" items: what to find out."""

    id: ItemId
    priority: Priority
    title: Short
    why: Text
    where: Where
    evidence: Annotated[list[Step], Field(max_length=8)] = Field(default_factory=list)
    fix: Fix
    question: Text | None = None
    prompt: Annotated[str, Field(min_length=1, max_length=3_000)]
    technical: Technical
    also_reported_by: Annotated[list[Short], Field(max_length=4)] = Field(default_factory=list)


class NotChecked(StrictModel):
    file: FilePath
    reason: Short  # plain words, for example "Polaris can't check Go files yet"


class OpenRoute(StrictModel):
    """A page or API route with no login check Polaris could see."""

    route: Short
    file: FilePath
    line: Line
    changes_data: bool
    problems: Count


class OtherTools(StrictModel):
    """Results imported from other tools' SARIF files (not verified by Polaris)."""

    tools: Annotated[list[Short], Field(max_length=16)] = Field(default_factory=list)
    results: Count
    agree_with_polaris: Count
    rejected_files: Count


class SinceLastCheck(StrictModel):
    """Compared with the previous check of the same scope, by stable item id."""

    fixed: Annotated[list[ItemId], Field(max_length=200)] = Field(default_factory=list)
    new: Annotated[list[ItemId], Field(max_length=200)] = Field(default_factory=list)
    still_open: Annotated[list[ItemId], Field(max_length=200)] = Field(default_factory=list)


class Counts(StrictModel):
    fix_now: Count
    check_this: Count
    worth_a_look: Count
    files_checked: Count
    files_not_checked: Count
    kinds_of_problems: Count


class CheckResult(StrictModel):
    """`status`: `clear` (nothing to fix now and everything was checked), `fix_needed` (at least
    one "fix now" item) or `incomplete` (nothing to fix now, but something couldn't be checked or
    files changed during the check). Exit codes follow it: 1 fix needed, 2 incomplete, 0 clear."""

    format: Literal["polaris.check/1"] = CHECK_FORMAT
    status: Status
    summary: Text
    scope: Scope
    scope_label: Short
    counts: Counts
    items: Annotated[list[CheckItem], Field(max_length=MAX_ITEMS)] = Field(default_factory=list)
    # Items found but not listed in full (over the limit), by priority.
    more: dict[Priority, Count] = Field(default_factory=dict)
    not_checked: Annotated[list[NotChecked], Field(max_length=50)] = Field(default_factory=list)
    open_routes: Annotated[list[OpenRoute], Field(max_length=20)] = Field(default_factory=list)
    other_tools: OtherTools | None = None
    since_last_check: SinceLastCheck | None = None
    next_steps: Annotated[list[Text], Field(max_length=12)] = Field(default_factory=list)
    notes: Annotated[list[Text], Field(max_length=12)] = Field(default_factory=list)
    # The full review behind this result, for the advanced tools (`polaris workflow review`).
    report_id: Short
    polaris_version: Short

    def exit_code(self) -> int:
        """1 when something must be fixed now, 2 when the check is incomplete, 0 when clear."""
        if self.counts.fix_now:
            return 1
        return 0 if self.status == "clear" else 2
