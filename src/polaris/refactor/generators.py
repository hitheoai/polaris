"""Where a candidate fix comes from. Every generator returns the whole edited file, never a patch.

A generator only proposes. Nothing it returns is trusted: the plan re-reviews it, locks its scope
and bounds its size before it is shown, and a person approves the exact result before anything
is written.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from polaris.integrations.forge.verify import apply_edit
from polaris.refactor.codemods import CODEMODS
from polaris.review.models import WorkflowFinding

Origin = Literal["suggested_edit", "codemod", "ai"]


@dataclass(frozen=True)
class Candidate:
    path: str
    replacement: str  # the whole file, edited
    origin: Origin
    name: str
    rationale: str


@dataclass(frozen=True)
class Declined:
    """A generator that tried and couldn't: recorded in the plan with its reason, never hidden."""

    origin: Origin
    name: str
    reason: str


class Generator(Protocol):
    origin: Origin

    def __call__(self, finding: WorkflowFinding, text: str) -> Candidate | Declined | None: ...


class SuggestedEdit:
    """The one-line edit an analyzer rule attached to the finding."""

    origin: Origin = "suggested_edit"

    def __call__(self, finding: WorkflowFinding, text: str) -> Candidate | None:
        edit = finding.suggested_edit
        if edit is None or "\r" in text:
            return None
        edited = apply_edit(text, edit.line, edit.original, edit.replacement)
        if edited is None:
            return None
        note = edit.note or "The rule's own suggested edit."
        return Candidate(finding.path, edited, self.origin, finding.rule_id, note[:4000])


class Codemod:
    """A deterministic multi-line fix for rules whose repair is mechanical (see codemods.py)."""

    origin: Origin = "codemod"

    def __call__(self, finding: WorkflowFinding, text: str) -> Candidate | None:
        for codemod in CODEMODS.get(finding.rule_id, ()):
            fix = codemod(text, finding.start_line)
            if fix is not None and fix.text != text:
                return Candidate(finding.path, fix.text, self.origin, fix.name, fix.rationale)
        return None


def deterministic() -> tuple[Generator, ...]:
    """The generators that need no model, work offline and always give the same answer."""
    return (SuggestedEdit(), Codemod())
