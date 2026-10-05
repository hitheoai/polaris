"""The terminal UI's view model: plain data in, (text, role) spans out. No Textual, no Rich.

Every displayed string from a review (paths, symbols, messages, snippets, labels, SARIF text) is
cleaned here (see `polaris.tui.text`); roles name a theme style, never a colour. Each state is
shown with a glyph and a word (see `polaris.tui.theme`), so nothing depends on colour alone.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from polaris.check.brand import NAME, STAR
from polaris.review.models import ImportedFinding, WorkflowFinding, valid_source_path
from polaris.tui import theme
from polaris.tui.session import ReviewData
from polaris.tui.source import Context, SourceIndex
from polaris.tui.text import clean, clean_block, plural

Span = tuple[str, str]
Line = tuple[Span, ...]
Group = Literal["issue", "question", "other"]
QUESTION_FLOOR = "medium"
SKIPPED_PATHS = ("__polaris",)
CHECK_CODES: dict[str, str] = {
    "sql_injection": "SQ", "command_injection": "CM", "code_injection": "CO", "xss": "XS", "ssrf": "SR",
    "open_redirect": "OR", "path_traversal": "PT", "secret_exposure": "SE", "missing_authorization": "AZ",
    "insecure_auth_crypto": "CR", "unsafe_security_configuration": "CF", "workflow_injection": "WI",
    "untrusted_checkout": "UC", "excessive_privileges": "EP", "unpinned_dependency": "UP",
    "unverified_download": "UD", "api_authorization": "GA",
}


def line(*spans: Span) -> Line:
    return tuple(span for span in spans if span[0])


def plain(value: Line) -> str:
    """The text of a line without styles (for tests and text renderings)."""
    return "".join(text for text, _ in value)


def plain_lines(lines: Iterable[Line]) -> str:
    return "\n".join(plain(item) for item in lines)


def state_span(state: theme.State, *, short: str | None = None) -> Span:
    return (f"{state.glyph} {short or state.word}", state.role)


def severity_span(value: str | None, *, short: bool = False) -> Span:
    state = theme.severity(value)
    name = value if value in theme.SEVERITY else "medium"
    return state_span(state, short=theme.SEVERITY_SHORT[name] if short else None)


def where(path: str, line_number: int | None, symbol: str | None = None) -> str:
    text = clean(path, 300) + (f":{line_number}" if line_number else "")
    if symbol and symbol != "<module>":
        text += f" in {clean(symbol, 120)}"
    return text


def tail(text: str, width: int) -> str:
    """Keep the end of a long location (the file name and line matter most)."""
    return text if len(text) <= width else "…" + text[len(text) - max(1, width - 1):]


def reason_text(code: str) -> str:
    from polaris.workflow.service import REASON_TEXT

    return REASON_TEXT.get(code, clean(code, 80).replace("_", " "))


# ---- findings -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Filters:
    """What the cockpit shows. The severity floor applies to flagged issues; "to verify"
    questions are their own group, shown from medium up (or from the floor, when it is lower),
    and `v` hides them."""

    floor: str = "high"
    questions: bool = True
    query: str = ""
    path: str | None = None

    def question_floor(self) -> str:
        return self.floor if theme.severity_rank(self.floor) > theme.severity_rank(QUESTION_FLOOR) else QUESTION_FLOOR


FLOORS: tuple[str, ...] = ("high", "medium", "low", "info", "critical")


def next_floor(current: str) -> str:
    return FLOORS[(FLOORS.index(current) + 1) % len(FLOORS)] if current in FLOORS else "high"


@dataclass(frozen=True)
class FindingRow:
    key: str
    finding: WorkflowFinding
    group: Group
    also: tuple[ImportedFinding, ...] = ()

    @property
    def severity(self) -> str:
        return self.finding.severity or "medium"

    def cells(self, where_width: int = 200) -> tuple[Line, Line, Line, Line]:
        finding = self.finding
        state = theme.RESULT.get(finding.result, theme.RESULT["error"])
        title = clean(finding.title, 120) or clean(finding.check_id, 60)
        extra: list[Span] = []
        if self.also:
            extra.append((f" ⇄{len(self.also)}", theme.MARKS["corroborated"].role))
        if finding.suggested_edit is not None:
            extra.append((f" {theme.MARKS['edit'].glyph}", theme.MARKS["edit"].role))
        return (
            line(severity_span(finding.severity, short=True)),
            line(state_span(state)),
            line((title, "text"), *extra),
            line((tail(where(finding.path, finding.start_line), where_width), "muted")),
        )


def _group(finding: WorkflowFinding) -> Group:
    if finding.result == "flagged":
        return "issue"
    if finding.result == "needs_context":
        return "question"
    return "other"


def _matches(finding: WorkflowFinding, query: str, path: str | None) -> bool:
    if path is not None and not (finding.path == path or (path.endswith("/") and finding.path.startswith(path))):
        return False
    if not query:
        return True
    needle = query.casefold()
    return any(needle in (value or "").casefold() for value in (
        finding.title, finding.path, finding.rule_id, finding.check_id, finding.message, finding.symbol,
        finding.severity, finding.cwe, finding.verify,
    ))


@dataclass(frozen=True)
class FindingView:
    rows: tuple[FindingRow, ...]
    issues_total: int
    issues_shown: int
    issues_below_floor: int
    questions_total: int
    questions_shown: int
    questions_below_floor: int
    other_shown: int
    filtered_out: int
    hidden: Mapping[str, int] = field(default_factory=dict)

    def status(self, filters: Filters) -> Line:
        floor = theme.severity(filters.floor)
        spans: list[Span] = [(f"{plural(self.issues_shown, 'issue')}", "label")]
        if self.issues_below_floor:
            spans.append((f", {self.issues_below_floor} below {floor.glyph} {floor.word}+ ", "muted"))
            spans.append(("(s)", "key"))
        else:
            spans.append((f" at {floor.glyph} {floor.word}+ ", "muted"))
            spans.append(("(s)", "key"))
        spans.append((" · ", "muted"))
        if filters.questions:
            spans.append((plural(self.questions_shown, "question"), "label"))
            if self.questions_below_floor:
                spans.append((f", {self.questions_below_floor} lower", "muted"))
        else:
            spans.append((f"{plural(self.questions_total, 'question')} hidden", "muted"))
        spans.append((" (v)", "key"))
        if self.other_shown:
            spans.append((f" · {self.other_shown} analysis error(s)", "result.error"))
        if filters.query or filters.path:
            scope = []
            if filters.path:
                scope.append(f"in {clean(filters.path, 60)}")
            if filters.query:
                scope.append(f"matching “{clean(filters.query, 40)}”")
            spans.append((f" · {' '.join(scope)}, {self.filtered_out} filtered out", "warning"))
            spans.append((" (/ esc)", "key"))
        hidden = [f"{count} {name}" for name, count in self.hidden.items() if count]
        if hidden:
            spans.append((" · hidden: " + ", ".join(hidden), "muted"))
        return line(*spans)


def finding_view(data: ReviewData, filters: Filters) -> FindingView:
    from polaris.review.sarif_import import corroborations

    review = data.envelope.review
    also = corroborations(review)
    order = {"issue": 0, "question": 1, "other": 2}
    candidates = sorted(
        (finding for finding in review.findings if finding.result != "ok"),
        key=lambda item: (order[_group(item)], theme.severity_rank(item.severity), item.path, item.start_line,
                          item.rule_id),
    )
    rows: list[FindingRow] = []
    seen: Counter[str] = Counter()
    issues = [item for item in candidates if _group(item) == "issue"]
    questions = [item for item in candidates if _group(item) == "question"]
    counts = {"issues_shown": 0, "issues_below": 0, "questions_shown": 0, "questions_below": 0, "other": 0,
              "filtered": 0}
    question_floor = filters.question_floor()
    for finding in candidates:
        group = _group(finding)
        if group == "issue" and not theme.at_least(finding.severity, filters.floor):
            counts["issues_below"] += 1
            continue
        if group == "question":
            if not filters.questions:
                continue
            if not theme.at_least(finding.severity, question_floor):
                counts["questions_below"] += 1
                continue
        if not _matches(finding, filters.query, filters.path):
            counts["filtered"] += 1
            continue
        seen[finding.finding_id] += 1
        key = finding.finding_id if seen[finding.finding_id] == 1 else f"{finding.finding_id}~{seen[finding.finding_id]}"
        rows.append(FindingRow(key, finding, group, tuple(also.get(finding.finding_id, ()))))
        counts[{"issue": "issues_shown", "question": "questions_shown", "other": "other"}[group]] += 1
    return FindingView(
        rows=tuple(rows), issues_total=len(issues), issues_shown=counts["issues_shown"],
        issues_below_floor=counts["issues_below"], questions_total=len(questions),
        questions_shown=counts["questions_shown"], questions_below_floor=counts["questions_below"],
        other_shown=counts["other"], filtered_out=counts["filtered"],
        hidden={"suppressed": review.summary.suppressed, "baselined": review.summary.baselined},
    )


# ---- file tree ----------------------------------------------------------------------------------

STATE_ORDER = ("not_checked", "partial", "checked", "excluded", "not_applicable")


@dataclass
class FileNode:
    path: str
    name: str
    directory: bool
    state: str = "not_applicable"
    language: str = ""
    issues: int = 0
    questions: int = 0
    worst: str | None = None
    children: dict[str, FileNode] = field(default_factory=dict)

    def label(self) -> Line:
        state = theme.COVERAGE.get(self.state, theme.COVERAGE["not_applicable"])
        spans: list[Span] = [(state.glyph + " ", state.role), (clean(self.name, 120) + ("/" if self.directory else ""),
                                                                "label" if self.directory else "text")]
        if self.issues:
            worst = theme.severity(self.worst)
            spans.append((f"  {self.issues}{worst.glyph}", worst.role))
        if self.questions:
            spans.append((f"  {self.questions}?", "result.verify"))
        return line(*spans)

    def sorted_children(self) -> list[FileNode]:
        return sorted(self.children.values(), key=lambda node: (not node.directory, node.name.casefold(), node.name))


def file_states(data: ReviewData) -> dict[str, tuple[str, str]]:
    """(coverage state, language) per reviewed path, from required coverage rows."""
    rows: dict[str, list[Any]] = {}
    for entry in data.envelope.review.coverage.entries:
        if entry.path.startswith(SKIPPED_PATHS):
            continue
        rows.setdefault(entry.path, []).append(entry)
    states: dict[str, tuple[str, str]] = {}
    for path, entries in rows.items():
        required = [entry for entry in entries if entry.required]
        language = entries[0].language
        if required:
            statuses = {entry.status for entry in required}
            if statuses == {"checked"}:
                state = "checked"
            elif "checked" in statuses or "partial" in statuses:
                state = "partial"
            else:
                state = "not_checked"
        elif any(entry.reason == "excluded" for entry in entries):
            state = "excluded"
        else:
            state = "not_applicable"
        states[path] = (state, language)
    return states


def file_tree(data: ReviewData, view: FindingView, *, limit: int = 20_000) -> FileNode:
    """Directories and files with their coverage state and the counts of visible findings."""
    states = file_states(data)
    paths = set(states) | {row.finding.path for row in view.rows}
    root = FileNode("", "", True)
    for path in sorted(paths)[:limit]:
        if not valid_source_path(path):
            continue
        node = root
        parts = path.split("/")
        for index, part in enumerate(parts):
            directory = index < len(parts) - 1
            key = part + ("/" if directory else "")
            if key not in node.children:
                prefix = "/".join(parts[: index + 1]) + ("/" if directory else "")
                node.children[key] = FileNode(prefix, part, directory)
            node = node.children[key]
        node.state, node.language = states.get(path, ("not_applicable", ""))
    for row in view.rows:
        found = _find(root, row.finding.path)
        if found is None:
            continue
        if row.group == "question":
            found.questions += 1
        else:
            found.issues += 1
            if found.worst is None or theme.severity_rank(row.finding.severity) < theme.severity_rank(found.worst):
                found.worst = row.severity
    _aggregate(root)
    return root


def _find(root: FileNode, path: str) -> FileNode | None:
    node = root
    parts = path.split("/")
    for index, part in enumerate(parts):
        node_next = node.children.get(part + ("/" if index < len(parts) - 1 else ""))
        if node_next is None:
            return None
        node = node_next
    return node


def _aggregate(node: FileNode) -> None:
    if not node.directory:
        return
    states = []
    for child in node.children.values():
        _aggregate(child)
        node.issues += child.issues
        node.questions += child.questions
        if child.worst is not None and (node.worst is None or theme.severity_rank(child.worst) < theme.severity_rank(node.worst)):
            node.worst = child.worst
        states.append(child.state)
    if not states:
        return
    reviewed = [state for state in states if state in ("not_checked", "partial", "checked")]
    if not reviewed:
        node.state = "excluded" if "excluded" in states else "not_applicable"
    elif set(reviewed) == {"checked"}:
        node.state = "checked"
    elif set(reviewed) == {"not_checked"}:
        node.state = "not_checked"
    else:
        node.state = "partial"


# ---- the detail pane ------------------------------------------------------------------------------

VerificationState = Any  # polaris.integrations.forge.verify.Verification, "pending", or None


def code_block(context: Context, *, gutter: bool = True) -> list[Line]:
    if not context.lines:
        return [line((context.note or "No code to show.", "muted"))]
    width = len(str(context.lines[-1].number))
    lines: list[Line] = []
    for item in context.lines:
        marker = ">" if item.flagged else " "
        number = f"{marker} {item.number:>{width}} │ " if gutter else ""
        lines.append(line((number, "code.flagged" if item.flagged else "code.number"),
                          (item.text or " ", "code.flagged" if item.flagged else "code")))
    if context.note:
        lines.append(line((context.note, "warning")))
    return lines


def origin_note(context: Context) -> str:
    return {
        "analyzed": "the exact text that was analyzed",
        "worktree": "worktree file, identical to the reviewed text",
        "snippet": "snippet stored in the report",
        "none": "no code available",
    }[context.origin]


def trace_summary(finding: WorkflowFinding) -> str | None:
    steps = list(finding.trace)
    if len(steps) < 2:
        return None
    parts = []
    for step in steps[:8]:
        place = f"line {step.line}" if not step.path or step.path == finding.path else f"{clean(step.path, 120)}:{step.line}"
        parts.append(f"{clean(step.label, 80)} ({place})")
    if len(steps) > 8:
        parts.append(f"… {len(steps) - 8} more")
    return " → ".join(parts)


def verification_line(finding: WorkflowFinding, data: ReviewData, verification: VerificationState) -> Line:
    if finding.suggested_edit is None:
        return ()
    if not data.live:
        return line(state_span(theme.VERIFICATION["saved"]), (" — re-verifying an edit needs a live review", "muted"))
    if verification == "pending":
        return line(state_span(theme.VERIFICATION["pending"]), ("…", "muted"))
    if verification is None:
        return line(state_span(theme.VERIFICATION["none"]), (" — press ", "muted"), ("f", "key"),
                    (" to re-review with the edit applied", "muted"))
    state = theme.VERIFICATION.get(verification.status, theme.VERIFICATION["inconclusive"])
    return line(state_span(state), (f" ({clean(verification.reason, 60).replace('_', ' ')})", "muted"))


def explanation(finding: WorkflowFinding) -> dict[str, str] | None:
    from polaris.review import catalog

    return catalog.explain(finding.rule_id) or catalog.explain(finding.check_id)


def detail_lines(
    row: FindingRow, data: ReviewData, sources: SourceIndex, *, verification: VerificationState = None,
    explain: bool = True,
) -> list[Line]:
    finding = row.finding
    result = theme.RESULT.get(finding.result, theme.RESULT["error"])
    lines: list[Line] = [
        line(severity_span(finding.severity), (" ", ""), state_span(result), ("  ", ""),
             (clean(finding.title, 160), "heading")),
        line((where(finding.path, finding.start_line, finding.symbol), "label")),
        (),
    ]
    lines.extend(line((text, "text")) for text in clean_block(finding.message, 1_200) if text)
    for detail in finding.details[:6]:
        lines.append(line(("· " + clean(detail, 300), "muted")))
    context = sources.context(finding.path, finding.start_line, end=min(finding.end_line, finding.start_line + 8),
                              before=3, after=3, finding=finding)
    lines.append(())
    lines.append(line(("Code", "label"), (f" — {origin_note(context)}", "muted")))
    lines.extend(code_block(context))
    summary = trace_summary(finding)
    if summary:
        lines.append(())
        lines.append(line(("Path ", "label"), (f"({len(finding.trace)} steps, press ", "muted"), ("t", "key"),
                          (" to walk it)", "muted")))
        lines.append(line((summary, "text")))
    if finding.result == "needs_context" and finding.verify:
        lines.append(())
        lines.append(line(("To verify: ", "result.verify"), (clean(finding.verify, 900), "text")))
        if finding.call_sites:
            shown = ", ".join(clean(site, 120) for site in finding.call_sites[:6])
            more = len(finding.call_sites) - 6
            lines.append(line(("Callers: ", "label"), (shown + (f" (+{more} more)" if more > 0 else ""), "text")))
    if finding.guidance:
        lines.append(())
        lines.append(line(("Fix: ", "label"), (clean(finding.guidance, 1_200), "text")))
    edit = finding.suggested_edit
    if edit is not None:
        lines.append(())
        note = f": {clean(edit.note, 200)}" if edit.note else ""
        lines.append(line((f"Suggested edit (line {edit.line}){note}", "label")))
        lines.append(line(("- ", "diff.remove"), (clean(edit.original.strip(), 400), "diff.remove")))
        lines.append(line(("+ ", "diff.add"), (clean(edit.replacement.strip(), 400), "diff.add")))
        lines.append(verification_line(finding, data, verification))
    if row.also:
        lines.append(())
        reporters = ", ".join(
            f"{clean(item.tool, 60)}{' ' + clean(item.rule_id, 100) if item.rule_id else ''} (line {item.start_line})"
            for item in row.also[:4])
        others = f" and {len(row.also) - 4} more" if len(row.also) > 4 else ""
        lines.append(line(("Also reported by: ", "imported"), (reporters + others, "text"),
                          (" — imported SARIF, not verified by Polaris", "muted")))
    info = explanation(finding) if explain else None
    if info:
        lines.append(())
        lines.append(line(("About this check", "heading"), (f" · {clean(info.get('title', ''), 80)}", "muted")))
        for key, label in (("what", "What"), ("why_it_matters", "Why it matters"), ("how_to_fix", "How to fix"),
                           ("vulnerable_example", "Vulnerable"), ("safer_example", "Safer")):
            value = info.get(key)
            if value:
                lines.append(line((f"{label}: ", "label"), (clean(value, 600), "text")))
    meta = [item for item in (
        clean(finding.rule_id, 120), clean(finding.cwe or "", 20),
        f"confidence {finding.confidence}" if finding.confidence else "", f"id {finding.finding_id}",
        clean(finding.analyzer_id, 60),
    ) if item]
    lines.append(())
    lines.append(line((" · ".join(meta), "muted")))
    if finding.suppression:
        lines.append(line((f"Suppressed: {clean(finding.suppression, 300)}", "warning")))
    return lines


# ---- the taint walk -------------------------------------------------------------------------------


@dataclass(frozen=True)
class WalkStep:
    index: int
    kind: str
    path: str
    line: int
    label: str
    context: Context

    def header(self, total: int) -> Line:
        state = theme.STEP.get(self.kind, theme.STEP["step"])
        return line((f"{self.index + 1}/{total} ", "muted"), state_span(state), ("  ", ""),
                    (where(self.path, self.line), "label"), ("  ", ""), (self.label, "text"))


def walk_steps(finding: WorkflowFinding, sources: SourceIndex) -> list[WalkStep]:
    steps = list(finding.trace) or []
    if not steps:
        return []
    walk = []
    for index, step in enumerate(steps):
        path = step.path or finding.path
        context = sources.context(path, step.line, before=2, after=2, finding=finding if path == finding.path else None)
        # The raw path is kept for opening the file; every display goes through `where`, which cleans it.
        walk.append(WalkStep(index, step.kind, path, step.line, clean(step.label, 200), context))
    return walk


def walk_lines(steps: Sequence[WalkStep], current: int) -> list[Line]:
    """Every step as a list (current one marked), for the step list pane."""
    total = len(steps)
    lines = []
    for step in steps:
        state = theme.STEP.get(step.kind, theme.STEP["step"])
        mark = "▶ " if step.index == current else "  "
        lines.append(line((mark, "key" if step.index == current else ""), state_span(state), ("  ", ""),
                          (where(step.path, step.line), "label" if step.index == current else "muted"),
                          ("  " + step.label, "text")))
    if not total:
        lines.append(line(("This finding has no data-flow trace.", "muted")))
    return lines


# ---- coverage -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class CoverageCell:
    state: str
    reason: str | None = None


@dataclass(frozen=True)
class CoverageRow:
    path: str
    language: str
    state: str
    cells: Mapping[str, CoverageCell]
    gap: str | None


def coverage_columns(data: ReviewData) -> list[str]:
    review = data.envelope.review
    columns = list(review.checks)
    if "api_authorization" not in columns and any(
            entry.check_id == "api_authorization" and entry.required for entry in review.coverage.entries):
        columns.append("api_authorization")
    return columns


def coverage_rows(
    data: ReviewData, *, only: Literal["all", "unreviewed", "excluded"] = "all", language: str | None = None,
) -> list[CoverageRow]:
    review = data.envelope.review
    columns = coverage_columns(data)
    entries: dict[str, list[Any]] = {}
    for entry in review.coverage.entries:
        if not entry.path.startswith(SKIPPED_PATHS):
            entries.setdefault(entry.path, []).append(entry)
    states = file_states(data)
    rows = []
    for path in sorted(entries):
        state, file_language = states[path]
        if language is not None and file_language != language:
            continue
        if only == "unreviewed" and state not in ("not_checked", "partial"):
            continue
        if only == "excluded" and state != "excluded":
            continue
        cells: dict[str, CoverageCell] = {}
        gap = None
        for check in columns:
            matching = [entry for entry in entries[path] if entry.check_id == check]
            required = [entry for entry in matching if entry.required]
            if required:
                worst = min(required, key=lambda entry: ("not_checked", "partial", "checked").index(entry.status)
                            if entry.status in ("not_checked", "partial", "checked") else 0)
                cells[check] = CoverageCell(worst.status, None if worst.status == "checked" else worst.reason)
                if worst.status != "checked" and gap is None:
                    gap = worst.reason
            elif matching:
                reason = matching[0].reason
                cell = "excluded" if reason == "excluded" else "not_implemented"
                cells[check] = CoverageCell(cell, reason)
            elif state == "excluded":
                cells[check] = CoverageCell("excluded", "excluded")
            else:
                cells[check] = CoverageCell("not_applicable", None)
        if gap is None and state == "excluded":
            gap = "excluded"
        if gap is None and state == "not_applicable":
            gap = next((entry.reason for entry in entries[path] if entry.status == "not_applicable"), None)
        rows.append(CoverageRow(path, file_language, state, cells, gap))
    return rows


def coverage_languages(data: ReviewData) -> list[str]:
    return sorted({language for _, language in file_states(data).values()})


def coverage_cell(cell: CoverageCell) -> Line:
    state = theme.COVERAGE.get(cell.state, theme.COVERAGE["not_applicable"])
    return line((state.glyph, state.role))


def coverage_file(row: CoverageRow, width: int = 200) -> Line:
    """The matrix's first cell: the file's overall state, then its path (end kept), like the tree."""
    state = theme.COVERAGE.get(row.state, theme.COVERAGE["not_applicable"])
    return line((f"{state.glyph} ", state.role), (tail(clean(row.path, 300), max(4, width - 2)), "text"))


def coverage_summary(data: ReviewData, rows: Sequence[CoverageRow]) -> Line:
    states = Counter(state for state, _ in file_states(data).values())
    spans: list[Span] = []
    for key in ("checked", "partial", "not_checked", "excluded", "not_applicable"):
        if states[key]:
            state = theme.COVERAGE[key]
            spans.append((f"{state.glyph} {states[key]} {state.word}   ", state.role))
    spans.append((f"({plural(len(rows), 'file')} shown)", "muted"))
    return line(*spans)


def cell_explanation(row: CoverageRow, check: str) -> Line:
    from polaris.review import catalog

    cell = row.cells.get(check, CoverageCell("not_applicable"))
    state = theme.COVERAGE.get(cell.state, theme.COVERAGE["not_applicable"])
    title = catalog.check_title(check)
    spans: list[Span] = [(f"{CHECK_CODES.get(check, '??')} {title}", "label"), (" on ", "muted"),
                         (clean(row.path, 200), "text"), (": ", "muted"), state_span(state)]
    if cell.reason and cell.state != "checked":
        spans.append((f" — {reason_text(cell.reason)}", "text"))
    elif cell.state == "not_applicable":
        spans.append((" — this check does not apply to this kind of file", "muted"))
    return line(*spans)


def legend(columns: Sequence[str]) -> Line:
    from polaris.review import catalog

    spans: list[Span] = []
    for check in columns:
        spans.append((CHECK_CODES.get(check, "??") + " ", "key"))
        spans.append((theme_title(catalog.check_title(check)) + "  ", "muted"))
    return line(*spans)


def theme_title(title: str) -> str:
    return title.split(" (")[0]


def what_ran(data: ReviewData, sources: SourceIndex | None = None) -> list[Line]:
    """Which analyzers and checks ran, on what, and what was left out (and why)."""
    from polaris.review import catalog
    from polaris.workflow.service import excluded_count, import_notes, unreviewed_scope

    envelope = data.envelope
    review = envelope.review
    summary = review.summary
    lines: list[Line] = [line(("What ran", "heading"))]
    unreviewed = unreviewed_scope(envelope)
    scope = [plural(summary.files_reviewed, "file") + " analyzed"]
    if summary.files_not_applicable:
        scope.append(f"{summary.files_not_applicable} not source code")
    excluded = excluded_count(envelope)
    if excluded:
        scope.append(f"{excluded} excluded by configuration")
    scope.append(f"{len(unreviewed)} not reviewed")
    context = sum(item.used_for_analysis for item in envelope.context.files)
    if context:
        scope.append(f"{plural(context, 'related file')} followed as context")
    lines.append(line(("Scope: ", "label"), (", ".join(scope), "text")))
    languages = ", ".join(f"{clean(name, 30)} {count}" for name, count in sorted(summary.languages.items())
                          if name != "unsupported")
    if languages:
        lines.append(line(("Languages: ", "label"), (languages, "text")))
    for path, reason in unreviewed[:8]:
        lines.append(line((f"{theme.COVERAGE['not_checked'].glyph} ", "cov.missing"), (clean(path, 200), "text"),
                          (f" — {reason_text(reason)}", "muted")))
    if len(unreviewed) > 8:
        lines.append(line((f"… {len(unreviewed) - 8} more not reviewed (Coverage tab, filter u)", "muted")))
    for omission in review.coverage.omissions:
        lines.append(line(("Limit: ", "warning"), (reason_text(omission), "text")))
    for note in import_notes(review):
        lines.append(line(("↗ ", "imported"), (clean(note, 300), "text")))
    if review.imports and not import_notes(review):
        for record in review.imports:
            lines.append(line(("↗ ", "imported"),
                              (f"SARIF {clean(record.name, 80)}: {record.imported} of "
                               f"{plural(record.results, 'result')} imported, not verified by Polaris", "text")))
    hidden = []
    if summary.suppressed:
        hidden.append(f"{summary.suppressed} suppressed inline (polaris-ignore)")
    if summary.baselined:
        hidden.append(f"{summary.baselined} in .polaris/baseline.json")
    if hidden:
        lines.append(line(("Hidden: ", "label"), (", ".join(hidden), "text")))
    if summary.suppressions_added:
        lines.append(line(("New suppressions: ", "warning"),
                          (f"{summary.suppressions_added} added in this change; confirm each one", "text")))
    if envelope.snapshot.omissions:
        lines.append(line(("Freshness: ", "warning"),
                          (f"{len(envelope.snapshot.omissions)} file(s) could not be bound to the snapshot", "text")))
    if sources is not None:
        matched = sources.worktree_summary()
        if matched is not None:
            same, total = matched
            if data.root is None:
                lines.append(line(("Worktree: ", "label"), ("no repository; code comes from stored snippets", "muted")))
            else:
                lines.append(line(("Worktree: ", "label"),
                                  (f"{same} of {plural(total, 'reviewed file')} unchanged since this report", "text")))
    lines.append(())
    lines.append(line(("Analyzers", "label")))
    for analyzer in review.capabilities.analyzers:
        available = analyzer.availability == "available"
        state = theme.COVERAGE["checked"] if available else theme.COVERAGE["not_implemented"]
        version = clean(analyzer.version or analyzer.expected_version, 60).split("/")[-1]
        languages = ", ".join(clean(item, 30) for item in analyzer.languages) or "—"
        status = f"{len(analyzer.checks)} checks" if available else clean(analyzer.availability, 30).replace("_", " ")
        lines.append(line((f"{state.glyph} ", state.role), (clean(analyzer.analyzer_id, 60), "label"),
                          (f" {version} · {languages} · {status}", "muted")))
    lines.append(())
    titles = ", ".join(theme_title(catalog.check_title(check)) for check in review.checks)
    lines.append(line((f"Checks ({len(review.checks)}): ", "label"), (titles, "text")))
    if not any(entry.check_id == "api_authorization" and entry.required for entry in review.coverage.entries):
        lines.append(line(("– Authorization guard regression: ", "muted"),
                          ("not run (needs a trusted --guard-policy)", "muted")))
    lines.append(())
    lines.append(line(("Static analysis only: nothing was executed and no model was used. Tests: not run. "
                       "No findings means these checks found nothing, not that the code is proven safe.", "muted")))
    return lines


# ---- trust bar, status and keys -------------------------------------------------------------------


@dataclass(frozen=True)
class Activity:
    running: bool = False
    elapsed: float | None = None
    failure: str | None = None


def seconds(value: float | None) -> str:
    if value is None:
        return ""
    if value < 1:
        return f"{value * 1000:.0f} ms"
    return f"{value:.1f}s" if value < 600 else f"{value / 60:.0f}m"


LABEL_MIN = 14
TRUST_ORDER = ("brand", "label", "head", "fresh", "complete", "repository", "offline", "elapsed")
# The compact brand mark, "✶ POLARIS": the widgets draw these two roles in the brand's colours
# (a gold star, the wordmark's gradient in the letters; see `polaris.tui.brand`).
BRAND_MARK: Line = ((STAR, "brand.star"), (" ", "text"), (NAME, "brand.name"))


def trust_parts(data: ReviewData | None, activity: Activity) -> dict[str, Line]:
    """Named parts of the trust bar; freshness and completeness are never dropped."""
    parts: dict[str, Line] = {"brand": BRAND_MARK}
    if data is not None:
        label = f"report {clean(data.report_name or '', 60)}" if data.mode == "saved" else clean(data.label, 60)
        parts["label"] = line((label, "text"))
        head = data.envelope.snapshot.head
        parts["head"] = line((f"HEAD {head[:7]}" if head else "no HEAD", "muted"))
    if activity.running:
        parts["fresh"] = line(state_span(theme.FRESHNESS["running"]))
    elif data is None and activity.failure is not None:
        parts["fresh"] = line(state_span(theme.FRESHNESS["failed"]))
    elif data is not None:
        if data.mode == "saved":
            parts["fresh"] = line(state_span(theme.FRESHNESS["saved"]))
        elif data.stale or data.envelope.snapshot.fresh is False:
            parts["fresh"] = line(state_span(theme.FRESHNESS["stale"]))
        else:
            parts["fresh"] = line(state_span(theme.FRESHNESS["fresh"]))
    if data is not None:
        complete = data.envelope.review.coverage.complete and data.envelope.snapshot.complete
        parts["complete"] = line(state_span(theme.COMPLETENESS["complete" if complete else "incomplete"]))
        if data.other_repository:
            parts["repository"] = line(("! other repository", "warning"))
    parts["offline"] = line(("offline · no model", "muted"))
    elapsed = activity.elapsed if activity.running else (data.elapsed_s if data is not None else None)
    if elapsed is not None:
        parts["elapsed"] = line((seconds(elapsed), "muted"))
    return parts


def _assemble(parts: Mapping[str, Line]) -> Line:
    spans: list[Span] = []
    for name in TRUST_ORDER:
        part = parts.get(name)
        if not part:
            continue
        if spans:
            spans.append((" · ", "muted"))
        spans.extend(part)
    return tuple(spans)


def trust_bar(data: ReviewData | None, activity: Activity, width: int = 200) -> Line:
    """The always-visible trust bar, fitted to `width` in stages: shorten the review label and
    HEAD, then drop elapsed time, HEAD, the label and "offline" in turn. The brand mark stays;
    only when even that is too wide does it shrink to its star, so freshness and completeness
    always show."""
    parts = dict(trust_parts(data, activity))

    def fits() -> bool:
        return len(plain(_assemble(parts))) <= width

    def shorten_label() -> None:
        label = parts.get("label")
        if label:
            text, role = label[0]
            keep = max(LABEL_MIN, len(text) - (len(plain(_assemble(parts))) - width))
            if keep < len(text):
                parts["label"] = ((text[: keep - 1] + "…", role),)

    def shorten_head() -> None:
        head = parts.get("head")
        if head and head[0][0].startswith("HEAD "):
            parts["head"] = ((head[0][0][5:], head[0][1]),)

    def star_only() -> None:
        parts["brand"] = BRAND_MARK[:1]

    stages = (
        shorten_label, shorten_head, lambda: parts.pop("elapsed", None), lambda: parts.pop("head", None),
        lambda: parts.pop("label", None), lambda: parts.pop("offline", None), star_only,
    )
    for stage in stages:
        if fits():
            break
        stage()
    return _assemble(parts)


@dataclass(frozen=True)
class UiState:
    """What the key bar needs to know to say which keys work, and why others don't."""

    mode: Literal["live", "saved", "none"] = "none"
    running: bool = False
    finding: WorkflowFinding | None = None
    editor: bool = False
    root: bool = False
    pull_request: bool = False
    verifications_left: int = 20


@dataclass(frozen=True)
class KeyHint:
    key: str
    label: str
    reason: str | None = None
    global_key: bool = False

    @property
    def available(self) -> bool:
        return self.reason is None

    @property
    def short_reason(self) -> str:
        return SHORT_REASONS.get(self.reason or "", self.reason or "")


EDITOR_REASON = "set $VISUAL or $EDITOR"
SHORT_REASONS = {
    "select a finding first": "no selection",
    EDITOR_REASON: "no $EDITOR",
    "no repository root for this report": "no repository",
    "this finding has no data-flow trace": "no trace",
    "no deterministic fix for this rule": "no fix",
    "saved report: run polaris tui without --report to review live": "saved report",
    "a review is already running": "running",
    "no review to save yet": "no review yet",
}


def notice(reason: str) -> str:
    """What pressing an unavailable key says: the full reason, and how to fix it where there's a way."""
    if reason == EDITOR_REASON:
        from polaris.tui.editor import MESSAGES

        return MESSAGES["editor_not_set"]
    return reason[:1].upper() + reason[1:] + "."


def availability(action: str, state: UiState) -> str | None:
    """None when `action` can run now, otherwise the reason it can't (shown in the key bar)."""
    finding = state.finding
    if action == "rerun":
        if state.mode == "saved":
            return "saved report: run polaris tui without --report to review live"
        if state.running:
            return "a review is already running"
        return None
    if action == "save":
        if state.mode == "none":
            return "no review to save yet"
        return None
    if action in ("open", "walk", "fix", "prompt") and finding is None:
        return "select a finding first"
    assert finding is not None or action not in ("open", "walk", "fix", "prompt")
    if action == "open":
        if not state.editor:
            return EDITOR_REASON
        if not state.root:
            return "no repository root for this report"
        return None
    if action == "walk":
        return None if finding is not None and finding.trace else "this finding has no data-flow trace"
    if action == "fix":
        if finding is not None and finding.suggested_edit is None:
            return "no deterministic fix for this rule"
        return None
    if action == "pr_option":
        if state.mode != "live" or not state.pull_request:
            return "needs a live pull-request review (polaris tui --base REV)"
        return None
    return None


CONTEXT_KEYS: dict[str, tuple[tuple[str, str, str], ...]] = {
    # (key, label, action)
    "findings": (("t", "walk", "walk"), ("f", "fix", "fix"), ("o", "open", "open"), ("y", "prompt", "prompt")),
    "tree": (("enter", "filter to file", "tree"),),
    "coverage": (("u", "unreviewed", "cov_unreviewed"), ("l", "language", "cov_language"),
                 ("x", "excluded", "cov_excluded"), ("a", "all", "cov_all")),
    "walk": (("n", "next", "next"), ("p", "previous", "previous"), ("g", "source", "first"), ("G", "sink", "last"),
             ("enter", "open", "open"), ("y", "prompt", "prompt"), ("esc", "back", "back")),
    "pr": (("i", "inline", "pr_option"), ("k", "questions", "pr_option"), ("g", "gate", "pr_option"),
           ("m", "imported", "pr_option"), ("e", "fail on imported", "pr_option"), ("u", "verify", "pr_option")),
    "surface": (("enter", "show finding", "surface"), ("o", "open handler", "surface")),
    "tools": (),
    "fix": (("o", "open at the edit", "open"), ("esc", "back", "back")),
}
GLOBAL_KEYS: tuple[tuple[str, str, str], ...] = (
    ("s", "floor", "floor"), ("v", "questions", "questions"), ("/", "filter", "filter"), ("r", "re-run", "rerun"),
    ("w", "save", "save"), ("?", "help", "help"), ("q", "quit", "quit"),
)


def key_hints(context: str, state: UiState, *, include_global: bool = True) -> list[KeyHint]:
    hints = [KeyHint(key, label, availability(action, state)) for key, label, action in CONTEXT_KEYS.get(context, ())]
    if include_global:
        hints.extend(KeyHint(key, label, availability(action, state), global_key=True)
                     for key, label, action in GLOBAL_KEYS)
    return hints


HELP_SECTIONS: tuple[tuple[str, tuple[tuple[str, str], ...]], ...] = (
    ("Everywhere", (
        ("?", "this help"), ("/", "filter findings by text (esc clears)"), (": or Ctrl+P", "commands"),
        ("1-5", "Findings, Coverage, Attack surface, Other tools, PR preview"),
        ("s", "severity floor for issues (high and above by default)"), ("v", "show or hide 'to verify' questions"),
        ("r", "re-run the review"), ("o", "open the file in $VISUAL/$EDITOR at the line"),
        ("w", "save the report as JSON (always a new file)"), ("Tab / Shift+Tab", "move between panes"),
        ("q", "quit"),
    )),
    ("Findings", (
        ("t", "taint walk: step from the untrusted source to the sink"),
        ("f", "fix preview: the one-line edit and whether a re-review confirms it"),
        ("y", "copy the prompt for your coding agent"), ("enter (tree)", "show only that file or folder"),
        ("enter (table)", "read the details"), ("esc", "clear the file and text filters"),
    )),
    ("Taint walk", (
        ("n / p", "next or previous step"), ("g / G", "jump to the source or the sink"),
        ("enter", "open the file at this step"), ("y", "copy the agent prompt"), ("esc", "back"),
    )),
    ("Coverage", (
        ("u", "only files not fully reviewed"), ("l", "cycle through languages"),
        ("x", "only excluded files"), ("a", "all files"), ("arrows", "pick a cell to see why it has that state"),
    )),
    ("Attack surface", (
        ("enter", "show the handler's first finding in Findings"), ("o", "open the handler in your editor"),
    )),
    ("PR preview (polaris tui --base REV)", (
        ("i", "lowest severity commented inline"), ("k", "comment inline on 'to verify' questions too"),
        ("g", "lowest severity that fails the gate"), ("m", "inline comments for imported results"),
        ("e", "imported results that fail the gate"), ("u", "re-verify suggested edits (one-click fixes)"),
    )),
    ("Fix preview", (
        ("f", "the one-line edit and whether a static re-review confirms it (live reviews)"),
        ("o", "open your editor at the edit"), ("esc", "back"),
    )),
)


def editor_hint() -> list[Line]:
    """How to set an editor, for the help screen when none is set."""
    from polaris.tui.editor import EXAMPLES

    return [
        line(("Opening files", "heading")),
        line(("  o opens files in $VISUAL or $EDITOR, and neither is set for this session. Quit, set one in "
              "your shell, then start polaris tui again, for example:", "text")),
        line((f"    {EXAMPLES[0]:<30}", "code"), ("VS Code (also cursor, codium)", "muted")),
        line((f"    {EXAMPLES[1]:<30}", "code"), ("or vim, nano, emacs, micro, hx", "muted")),
        line(("  Add the line to your shell profile (~/.zshrc, ~/.bashrc) to keep it.", "muted")),
        (),
    ]


def help_lines(state: UiState) -> list[Line]:
    lines: list[Line] = []
    for index, (title, keys) in enumerate(HELP_SECTIONS):
        lines.append(line((title, "heading")))
        lines.extend(line((f"  {key:<16}", "key"), (text, "text")) for key, text in keys)
        lines.append(())
        if index == 0 and not state.editor:
            lines.extend(editor_hint())  # right after the keys that open files, so it's on the first page
    blocked = [hint for context in ("findings", "walk") for hint in key_hints(context, state) if not hint.available]
    if blocked:
        lines.append(line(("Unavailable right now", "heading")))
        seen = set()
        for hint in blocked:
            if hint.key not in seen:
                seen.add(hint.key)
                lines.append(line((f"  ⊘ {hint.key:<14}", "muted"), (hint.reason or "", "text")))
        lines.append(())
    lines.append(line(("Glyphs (every state also has a word)", "heading")))
    legend_rows: tuple[tuple[str, Iterable[theme.State]], ...] = (
        ("Severity", theme.SEVERITY.values()),
        ("Result", [theme.RESULT[key] for key in ("flagged", "needs_context", "error")]),
        ("Coverage", [theme.COVERAGE[key] for key in (
            "checked", "partial", "not_checked", "not_implemented", "not_applicable", "excluded")]),
        ("Marks", theme.MARKS.values()),
        ("Review", [*theme.FRESHNESS.values(), *theme.COMPLETENESS.values()]),
        ("Fix", theme.VERIFICATION.values()), ("Walk", theme.STEP.values()),
    )
    for label, glyphs in legend_rows:
        spans: list[Span] = [(f"  {label:<10}", "label")]
        for glyph in glyphs:
            spans.extend((state_span(glyph), ("   ", "")))
        lines.append(line(*spans))
    lines.append(())
    lines.append(line(("Safety", "heading")))
    for text in (
        "Read-only: nothing from the repository is executed, and no model is used.",
        "The only actions: opening your editor (o, or enter in the walk), copying a prompt (y), and saving "
        "the report to a new file (w). Each needs a key press.",
        "Repository and SARIF text is shown as plain text: markup, escape codes and bidirectional controls "
        "are displayed (as \ufffd), never interpreted.",
    ):
        lines.append(line(("  " + text, "text")))
    return lines


def key_bar(hints: Iterable[KeyHint], width: int = 1_000) -> Line:
    """The focused pane's keys, each unavailable one with why (marked ⊘, never colour alone),
    then the global keys that fit; "? help" and "q quit" always stay."""
    hints = list(hints)
    essential = [hint for hint in hints if hint.key == "esc" or (hint.global_key and hint.key in ("?", "q"))]
    local = [hint for hint in hints if not hint.global_key and hint not in essential]
    others = [hint for hint in hints if hint.global_key and hint not in essential]

    def chunk(hint: KeyHint, *, long: bool) -> list[Span]:
        if hint.available:
            return [(hint.key, "key"), (f" {hint.label}  ", "text")]
        reason = hint.reason if long else hint.short_reason
        return [(f"⊘ {hint.key} ", "muted"), (f"{hint.label}: {reason}  ", "muted")]

    def size(spans: Sequence[Span]) -> int:
        return sum(len(text) for text, _ in spans)

    tail = [span for hint in essential for span in chunk(hint, long=False)]
    globals_ = [span for hint in others for span in chunk(hint, long=False)]
    detailed = [span for hint in local for span in chunk(hint, long=True)]
    if size(detailed) + size(globals_) + size(tail) <= width:
        return line(*detailed, *globals_, *tail)
    chunks = [chunk(hint, long=False) for hint in local]
    while chunks and sum(size(item) for item in chunks) + size(tail) > width:
        chunks.pop()  # the pane's last keys give way before help and quit do
    spans = [span for item in chunks for span in item]
    for hint in others:
        extra = chunk(hint, long=False)
        if size(spans) + size(extra) + size(tail) <= width:
            spans.extend(extra)
    return line(*spans, *tail)
