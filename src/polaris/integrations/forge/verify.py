"""Re-verify a finding's deterministic suggested edit before offering it as a one-click change.

An edit qualifies only when, in the same in-memory analysis setup:

1. a control re-review without the edit reproduces the finding (so its disappearance means
   something), and the file's required checks complete;
2. a re-review with the edit applied no longer detects that finding, still completes every
   required check (a syntax error would also make a finding vanish), and reports nothing new.

This is static re-review only: nothing is executed, written to disk or sent anywhere, and a
verified edit is not proof that behavior is correct. Behavioral tests are not run.
"""

from __future__ import annotations

import difflib
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from typing import Literal

from polaris.integrations.forge.markdown import safe_suggestion
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.engine import WorkflowReviewer
from polaris.review.js.tsconfig import is_config
from polaris.review.models import SourceFile, WorkflowFinding, WorkflowReviewReport
from polaris.workflow.service import WorkspaceReview

VerificationStatus = Literal["verified", "still_detected", "adds_findings", "inconclusive", "not_applicable"]
OPEN_RESULTS = ("flagged", "needs_context")
# Built-in analyzers only: no external analyzer, temporary source copies or worker processes.
MEMORY_ONLY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)


@dataclass(frozen=True)
class Verification:
    status: VerificationStatus
    reason: str


def apply_edit(text: str, line: int, original: str, replacement: str) -> str | None:
    """Replace exactly one line, keeping its line ending; None if the line no longer matches."""
    lines = text.splitlines(keepends=True)
    if not 1 <= line <= len(lines):
        return None
    current = lines[line - 1]
    body = current.rstrip("\n")
    if body != original:
        return None
    lines[line - 1] = replacement + current[len(body):]
    return "".join(lines)


def _open(report: WorkflowReviewReport, path: str) -> list[WorkflowFinding]:
    return [finding for finding in report.findings if finding.path == path and finding.result in OPEN_RESULTS]


def _checked(report: WorkflowReviewReport, path: str) -> bool:
    rows = [entry for entry in report.coverage.entries if entry.path == path and entry.required]
    return bool(rows) and all(entry.status == "checked" for entry in rows)


def _same(finding: WorkflowFinding, other: WorkflowFinding, *, distance: int = 0) -> bool:
    return (finding.rule_id == other.rule_id and finding.check_id == other.check_id
            and abs(finding.start_line - other.start_line) <= distance)


def _moved_lines(original: str, edited: str) -> list[tuple[int, int, int]]:
    """(first, end, shift) for each run of lines the edit left alone (0-based, end exclusive)."""
    matcher = difflib.SequenceMatcher(a=original.splitlines(), b=edited.splitlines(), autojunk=False)
    return [(a, a + size, b - a) for a, b, size in matcher.get_matching_blocks() if size and b != a]


def _shifted(line: int, moved: list[tuple[int, int, int]]) -> int:
    for first, end, shift in moved:
        if first <= line - 1 < end:
            return line + shift
    return line


def _judge(
    reviewer: WorkflowReviewer, subject: SourceFile, context: Sequence[SourceFile],
    control: WorkflowReviewReport | None, finding: WorkflowFinding, edited_text: str,
) -> tuple[Verification, WorkflowReviewReport]:
    """Judge one replacement of `subject`'s text: the shared core of every re-verification.

    The control review (the original text, same context) is returned so callers can reuse it for
    other candidates of the same file.
    """
    path = finding.path
    if control is None:
        control = reviewer.review_sources([subject, *context])
    before = _open(control, path)
    if not _checked(control, path) or not any(
            _same(finding, other) and other.result == finding.result for other in before):
        return Verification("inconclusive", "not_reproduced_in_isolation"), control
    edited = reviewer.review_sources([replace(subject, after=edited_text), *context])
    if not _checked(edited, path):
        return Verification("inconclusive", "edited_file_not_fully_checked"), control
    after = _open(edited, path)
    if any(_same(finding, other, distance=1) for other in after):
        return Verification("still_detected", "finding_still_detected"), control
    known = {(other.rule_id, other.check_id, other.start_line) for other in before}
    unknown = [other for other in after if (other.rule_id, other.check_id, other.start_line) not in known]
    if unknown and subject.after is not None:
        # A fix that adds or removes lines moves the problems below it; they are not new.
        moved = _moved_lines(subject.after, edited_text)
        known |= {(other.rule_id, other.check_id, _shifted(other.start_line, moved)) for other in before}
        unknown = [other for other in unknown if (other.rule_id, other.check_id, other.start_line) not in known]
    if unknown:
        return Verification("adds_findings", "edit_adds_findings"), control
    return Verification("verified", "no_longer_detected"), control


class Reverifier:
    """Re-review whole-file replacements for flagged findings, in memory, against one review.

    The same checks as `verify_edits` (control reproduces the finding, the edited file is fully
    checked, the finding is gone, nothing new appears) for any replacement text, not only a
    rule's one-line edit. Built-in analyzers only; nothing is executed, written or sent anywhere.
    """

    def __init__(self, review: WorkspaceReview) -> None:
        self._review = review
        self._reviewed = {source.path: source for source in review.sources
                          if source.role == "review" and source.after is not None and source.skip is None}
        self._configs = [replace(source, role="context") for source in self._reviewed.values()
                         if is_config(source.path)]
        self._reviewer = WorkflowReviewer(config=review.config, runtime=MEMORY_ONLY, guard_policy=None)
        self._controls: dict[tuple[str, frozenset[str]], WorkflowReviewReport] = {}

    def text_of(self, path: str) -> str | None:
        source = self._reviewed.get(path)
        return source.after if source is not None else None

    def baseline(self, paths: Iterable[str]) -> dict[tuple[str, str], int]:
        """Open findings per (path, check) as the post-apply check sees these files today.

        It reviews the files alone, as `workflow.repair.static_adapter` does, so anything counted
        here was already there before a fix and is not caused by it.
        """
        sources = [replace(source, role="review", changed_lines=None) for path in sorted(set(paths))
                   if (source := self._reviewed.get(path)) is not None]
        if not sources:
            return {}
        report = self._reviewer.review_sources([SourceFile(source.path, source.after or "", None) for source in sources])
        return dict(Counter((item.path, item.check_id) for item in report.findings if item.result != "ok"))

    def verify(self, finding: WorkflowFinding, edited_text: str) -> Verification:
        path = finding.path
        target = self._reviewed.get(path)
        if target is None or target.after is None:
            return Verification("not_applicable", "source_unavailable")
        if "\r" in target.after:
            return Verification("not_applicable", "carriage_returns")
        if edited_text == target.after:
            return Verification("not_applicable", "no_change")
        if finding.result not in OPEN_RESULTS:
            return Verification("not_applicable", "not_an_open_finding")
        crossed = {step.path for step in finding.trace if step.path and step.path != path}
        context = [replace(self._reviewed[name], role="context") for name in sorted(crossed) if name in self._reviewed]
        context.extend(item for item in (*self._review.context_sources, *self._configs) if item.path != path)
        subject = replace(target, changed_lines=None)
        key = (path, frozenset(crossed))
        verdict, control = _judge(self._reviewer, subject, context, self._controls.get(key), finding, edited_text)
        self._controls[key] = control
        return verdict


def verify_edits(
    review: WorkspaceReview, findings: Sequence[WorkflowFinding], *, limit: int = 20,
) -> dict[str, Verification]:
    """Verification per finding_id for findings that carry a `suggested_edit`."""
    if not 0 <= limit <= 50:
        raise ValueError("verification limit outside supported bounds")
    results: dict[str, Verification] = {}
    reviewed = {source.path: source for source in review.sources
                if source.role == "review" and source.after is not None and source.skip is None}
    configs = [replace(source, role="context") for source in reviewed.values() if is_config(source.path)]
    reviewer = WorkflowReviewer(config=review.config, runtime=MEMORY_ONLY, guard_policy=None)
    by_path: dict[str, list[WorkflowFinding]] = {}
    for finding in findings:
        if finding.suggested_edit is not None and finding.result in OPEN_RESULTS:
            by_path.setdefault(finding.path, []).append(finding)
    budget = limit
    for path, candidates in sorted(by_path.items()):
        target = reviewed.get(path)
        if target is None or target.after is None:
            results.update({item.finding_id: Verification("not_applicable", "source_unavailable") for item in candidates})
            continue
        if "\r" in target.after:
            results.update({item.finding_id: Verification("not_applicable", "carriage_returns") for item in candidates})
            continue
        # The same related context as the original review, plus changed files the traces cross.
        crossed = {step.path for item in candidates for step in item.trace if step.path and step.path != path}
        context = [replace(reviewed[name], role="context") for name in sorted(crossed) if name in reviewed]
        context.extend(item for item in (*review.context_sources, *configs) if item.path != path)
        subject = replace(target, changed_lines=None)
        control: WorkflowReviewReport | None = None
        for finding in candidates:
            edit = finding.suggested_edit
            assert edit is not None
            if not safe_suggestion(edit.replacement) or edit.replacement == edit.original:
                results[finding.finding_id] = Verification("not_applicable", "replacement_not_a_safe_single_line")
                continue
            edited_text = apply_edit(target.after, edit.line, edit.original, edit.replacement)
            if edited_text is None:
                results[finding.finding_id] = Verification("not_applicable", "source_line_mismatch")
                continue
            if budget <= 0:
                results[finding.finding_id] = Verification("inconclusive", "verification_limit")
                continue
            budget -= 1
            results[finding.finding_id], control = _judge(reviewer, subject, context, control, finding, edited_text)
    return results
