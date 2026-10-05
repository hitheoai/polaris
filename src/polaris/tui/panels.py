"""View functions for the PR preview, the fix preview, other tools' results and the attack surface.

Plain data in, (text, role) lines out, like `polaris.tui.view`: no Textual or Rich, every string
from a review cleaned, and every state shown with a glyph and a word.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from polaris.review.models import EntryPoint, WorkflowFinding
from polaris.tui import theme
from polaris.tui.prpreview import PLACEHOLDER_PULL_REQUEST, PLACEHOLDER_REPOSITORY, PlanState
from polaris.tui.session import ReviewData
from polaris.tui.source import SourceIndex
from polaris.tui.text import clean, clean_code_line, plural
from polaris.tui.view import Line, Span, line, severity_span, state_span, tail, where

# ---- the PR preview ----------------------------------------------------------------------------------


def _floor(value: str) -> str:
    state = theme.severity(value)
    return f"{state.glyph} {state.word}+"


def packed(chunks: Sequence[Sequence[Span]], width: int) -> list[Line]:
    """Chunks on as few lines as fit `width`, each chunk kept whole (never split mid-option)."""
    lines: list[Line] = []
    current: list[Span] = []
    size = 0
    for chunk in chunks:
        length = sum(len(text) for text, _ in chunk)
        if current and size + length > width:
            lines.append(line(*current))
            current, size = [], 0
        current.extend(chunk)
        size += length
    if current:
        lines.append(line(*current))
    return lines


def plan_columns(width: int) -> list[tuple[str, int]]:
    """PR preview table columns that fit `width` (1-cell padding each side, and a scrollbar)."""
    budget = max(40, width - 9)
    comment = 30 if budget >= 100 else 24
    return [("Sev", 6), ("Kind", 10), ("Comment", comment), ("Where", max(12, budget - 16 - comment))]


def surface_columns(width: int) -> list[tuple[str, int]]:
    """Attack surface table columns that fit `width` (1-cell padding each side, and a scrollbar)."""
    budget = max(40, width - 11)
    handler, reaches = (22, 18) if budget >= 100 else (16, 16) if budget >= 80 else (10, 14)
    return [("Guard", 15), ("Handler", handler), ("Where", max(12, budget - 23 - handler - reaches)),
            ("Reaches", reaches), ("Findings", 8)]


def plan_header(
    plan: Any, state: PlanState, data: ReviewData, *, computing: bool = False, width: int = 200,
) -> list[Line]:
    """Most important first, since a small terminal shows only the top of it: what this is, the
    gate, the options the keys change, then the reviewed commits and suggestion counts."""
    pull_request = data.pull_request
    if width >= 94:
        lines: list[Line] = [line(
            ("Local preview · ", "warning"),
            (f"placeholder repository {PLACEHOLDER_REPOSITORY}, PR #{PLACEHOLDER_PULL_REQUEST}", "warning"),
            (" · nothing is published", "warning"),
        )]
    else:
        lines = [line((f"Local preview, nothing is published (placeholder {PLACEHOLDER_REPOSITORY} "
                       f"#{PLACEHOLDER_PULL_REQUEST})", "warning"))]
    if computing:
        lines.append(line(state_span(theme.FRESHNESS["running"], short="recomputing the plan…"),))
    if plan is not None:
        gate = theme.GATE.get(plan.gate, theme.GATE["incomplete"])
        counts = plan.counts
        lines.append(line(("Gate ", "label"), state_span(gate),
                          (f" · {counts.inline} inline", "text"),
                          (f" · {plural(counts.issues_in_change, 'issue')}, "
                           f"{plural(counts.questions_in_change, 'question')} in the change", "text"),
                          (f" · {counts.existing_in_changed_files} already present", "muted"),
                          (f" · {counts.lower_severity_in_change} below the inline floor", "muted")))
    lines.extend(packed([
        (("i", "key"), (f" inline {_floor(state.min_inline_severity)}  ", "text")),
        (("k", "key"), (f" questions inline: {'on' if state.inline_questions else 'off'}  ", "text")),
        (("g", "key"), (f" gate {_floor(state.fail_severity)}  ", "text")),
        (("m", "key"), (f" imported inline: {state.inline_imported}  ", "text")),
        (("e", "key"), (f" fail on imported: {state.fail_on_imported or 'off'}  ", "text")),
        (("u", "key"), (f" verify fixes: {'on' if state.verify_fixes else 'off'}", "text")),
    ], width))
    if pull_request is not None:
        lines.append(line(("Reviewed ", "muted"), (pull_request.head_sha[:12], "label"), (" against merge base ", "muted"),
                          (pull_request.merge_base[:12], "label"), (" (offline; no forge, network or token)", "muted")))
    if plan is not None:
        counts = plan.counts
        suggestions = f"Suggestions: {counts.suggestions_verified} verified, {counts.suggestions_withheld} withheld"
        if counts.imported_in_change or counts.imports_rejected:
            suggestions += (f" · {counts.imported_in_change} imported result(s) on changed lines "
                            f"({counts.imported_inline} inline, {counts.imports_rejected} SARIF file(s) rejected)")
        lines.append(line((suggestions, "muted")))
    return lines


def plan_unavailable(data: ReviewData | None) -> list[Line]:
    if data is not None and data.mode == "saved":
        reason = "A saved report can't be turned into a PR preview: it needs the pull request's changed lines and a live review."
    else:
        reason = "The PR preview needs a pull-request review."
    return [line((reason, "text")), (),
            line(("Run ", "muted"), ("polaris tui --base main", "key"), (" (and ", "muted"), ("--head REV", "key"),
                 (", default HEAD) to see the inline comments, summary and gate the PR bot would post, computed "
                  "offline.", "muted"))]


def plan_rows(plan: Any, where_width: int = 200) -> list[tuple[str, tuple[Line, Line, Line, Line]]]:
    """(key, cells) for the summary and each inline comment, as the bot would post them."""
    rows: list[tuple[str, tuple[Line, Line, Line, Line]]] = [(
        "summary", (line(("≡", "label")), line(("summary", "label")), line(("the summary comment", "text")),
                    line((plural(len(plan.summary.splitlines()), "line"), "muted"))),
    )]
    for index, comment in enumerate(plan.comments):
        if comment.origin == "imported":
            kind = line(("↗ imported", "imported"))
        elif comment.suggestion == "verified":
            kind = line(("✎ verified", "cov.checked"))
        elif comment.suggestion == "withheld":
            kind = line(("✎ withheld", "cov.partial"))
        elif comment.result == "needs_context":
            kind = line(state_span(theme.RESULT["needs_context"]))
        else:
            kind = line(state_span(theme.RESULT["flagged"]))
        rows.append((f"comment-{index}", (line(severity_span(comment.severity, short=True)), kind,
                                          line((clean(comment.title, 120), "text")),
                                          line((tail(where(comment.path, comment.line), where_width), "muted")))))
    return rows


def markdown_lines(text: str) -> list[Line]:
    """Markdown exactly as posted (raw, inert): headings bold, fenced code kept as code."""
    lines: list[Line] = []
    fenced = False
    for raw in text.split("\n")[:2_000]:
        value = clean_code_line(raw)
        if value.lstrip().startswith("```"):
            fenced = not fenced
            lines.append(line((value, "code.number")))
        elif fenced:
            lines.append(line((value or " ", "code")))
        elif value.startswith("#"):
            lines.append(line((value, "heading")))
        elif value.startswith("<sub>") or value.startswith("<details>") or value.startswith("</details>"):
            lines.append(line((value, "muted")))
        else:
            lines.append(line((value, "text")))
    return lines


def plan_body(plan: Any, key: str) -> list[Line]:
    if key == "summary":
        return [line(("Summary comment (edited in place on every push)", "label")), (), *markdown_lines(plan.summary)]
    index = int(key.split("-")[1])
    comment = plan.comments[index]
    return [line((f"Inline comment at {where(comment.path, comment.line)} (right side of the diff)", "label")), (),
            *markdown_lines(comment.body)]


# ---- the fix preview ---------------------------------------------------------------------------------

FIX_EXPLANATIONS = {
    "no_longer_detected": "With this edit applied, a static re-review no longer detects the finding and reports "
                          "nothing new. Tests were not run.",
    "finding_still_detected": "A static re-review still detects the finding with this edit applied.",
    "edit_adds_findings": "A static re-review reports a new finding with this edit applied.",
    "not_reproduced_in_isolation": "The finding wasn't reproduced when the file was re-reviewed on its own, so its "
                                   "disappearance would prove nothing.",
    "edited_file_not_fully_checked": "The edited file could not be fully checked (a syntax error would also make a "
                                     "finding vanish).",
    "verification_limit": "The verification limit for this review was reached (20 per review, as in pr plan); press "
                          "r to review again.",
    "verification_failed": "The re-review could not complete.",
    "replacement_not_a_safe_single_line": "The replacement isn't a single line that is safe to offer verbatim.",
    "source_line_mismatch": "The line no longer matches the analyzed text.",
    "carriage_returns": "The file uses carriage returns, which a one-line suggestion can't preserve.",
    "source_unavailable": "The analyzed text of this file isn't available.",
}


def fix_lines(
    finding: WorkflowFinding, data: ReviewData, sources: SourceIndex, verification: Any, *, left: int,
) -> list[Line]:
    edit = finding.suggested_edit
    lines: list[Line] = [
        line(severity_span(finding.severity), (" ", ""), state_span(theme.RESULT.get(finding.result, theme.RESULT["error"])),
             ("  ", ""), (clean(finding.title, 160), "heading")),
        line((where(finding.path, finding.start_line, finding.symbol), "label")), (),
    ]
    if edit is None:
        lines.append(line(("This rule has no deterministic one-line fix; see the guidance in the details.", "muted")))
        return lines
    note = f" — {clean(edit.note, 300)}" if edit.note else ""
    lines.append(line((f"Suggested edit at line {edit.line}{note}", "label")))
    context = sources.context(finding.path, edit.line, before=2, after=2, finding=finding)
    width = len(str(edit.line + 2))
    for item in context.lines:
        if item.number == edit.line:
            lines.append(line((f"- {item.number:>{width}} │ ", "diff.remove"), (clean_code_line(edit.original) or " ", "diff.remove")))
            lines.append(line((f"+ {item.number:>{width}} │ ", "diff.add"), (clean_code_line(edit.replacement) or " ", "diff.add")))
        else:
            lines.append(line((f"  {item.number:>{width}} │ ", "code.number"), (item.text or " ", "code")))
    if not context.lines:
        lines.append(line(("- ", "diff.remove"), (clean_code_line(edit.original), "diff.remove")))
        lines.append(line(("+ ", "diff.add"), (clean_code_line(edit.replacement), "diff.add")))
    if context.note:
        lines.append(line((context.note, "warning")))
    lines.append(())
    if not data.live:
        lines.append(line(state_span(theme.VERIFICATION["saved"]), (
            " — re-verifying the edit re-runs the analyzers on the exact analyzed text, so it needs a live review "
            "(polaris tui without --report).", "muted")))
    elif verification == "pending":
        lines.append(line(state_span(theme.VERIFICATION["pending"]), (" — re-reviewing the file in memory with the "
                                                                     "edit applied…", "muted")))
    elif verification is None:
        lines.append(line(state_span(theme.VERIFICATION["none"]), (f" — {left} verification(s) left for this review", "muted")))
    else:
        state = theme.VERIFICATION.get(verification.status, theme.VERIFICATION["inconclusive"])
        lines.append(line(state_span(state)))
        lines.append(line((FIX_EXPLANATIONS.get(verification.reason, clean(verification.reason, 80).replace("_", " ")),
                           "text")))
    lines.append(())
    lines.append(line(("Nothing is applied or executed: the re-review runs the built-in analyzers in memory. To apply "
                       "an edit, use your editor (o) or `polaris workflow propose`/`apply` with an approved digest.",
                       "muted")))
    return lines


# ---- other tools -------------------------------------------------------------------------------------


def tools_lines(data: ReviewData) -> list[Line]:
    """Imported SARIF results next to Polaris's: corroborated, tool-only, Polaris-only, left out, rejected."""
    from polaris.review.sarif_import import ERRORS as SARIF_ERRORS
    from polaris.review.sarif_import import by_tool

    review = data.envelope.review
    if not review.imports:
        return [line(("No SARIF was imported.", "label")), (),
                line(("Add ", "muted"), ("--import-sarif PATH", "key"), (" (repeatable) to compare other tools' "
                     "results with Polaris's. Polaris never runs those tools; their results are untrusted data.",
                     "muted"))]
    findings = {finding.finding_id: finding for finding in review.findings}
    corroborated = [item for item in review.imported if item.corroborates is not None]
    tool_only = [item for item in review.imported if item.corroborates is None]
    confirmed = {item.corroborates for item in corroborated}
    polaris_only = [finding for finding in review.findings
                    if finding.result in ("flagged", "needs_context") and finding.finding_id not in confirmed]
    lines: list[Line] = []

    def heading(key: str, count: int, text: str) -> None:
        state = theme.IMPORT_GROUP[key]
        if lines:
            lines.append(())
        lines.append(line(state_span(state), (f" ({count})", "label"), (f" — {text}", "muted")))

    heading("corroborated", len(corroborated), "another tool reports the same weakness at the same place")
    for item in corroborated:
        finding = findings.get(item.corroborates or "")
        target = (f"{clean(finding.title, 80)} ({theme.severity(finding.severity).word})" if finding is not None
                  else "a Polaris finding")
        lines.append(line(("  ", ""), (clean(item.tool, 60), "label"), (f" {clean(item.rule_id or 'no rule id', 100)}", "text"),
                          (f" · {where(item.path, item.start_line)} ⇄ ", "muted"), (target, "text")))
    heading("tool_only", len(tool_only), "reported only by another tool; Polaris did not verify these")
    for tool, items in by_tool(tool_only):
        version = f" {clean(items[0].tool_version, 40)}" if items[0].tool_version else ""
        lines.append(line(("  ", ""), (clean(tool, 80) + version, "label"), (f" ({len(items)})", "muted")))
        for item in items[:200]:
            rating = f" {item.severity}" + (f" ({item.security_severity:.1f})" if item.security_severity is not None else "")
            lines.append(line(("    ", ""), (item.level.upper(), "warning" if item.level == "error" else "muted"),
                              (f" · {clean(item.rule_id or 'no rule id', 100)} · {where(item.path, item.start_line)} · "
                               f"{item.category}{rating} — ", "muted"), (clean(item.message, 300), "text")))
    heading("polaris_only", len(polaris_only), "no imported tool reported these")
    for finding in polaris_only[:200]:
        lines.append(line(("  ", ""), severity_span(finding.severity, short=True), (f"  {clean(finding.title, 80)}", "text"),
                          (f" · {where(finding.path, finding.start_line)}", "muted")))
    dropped = [(record, reason, count) for record in review.imports for reason, count in record.dropped.items()]
    heading("dropped", sum(count for _, _, count in dropped), "results each import left out, by reason")
    for record, reason, count in dropped:
        lines.append(line(("  ", ""), (clean(record.name, 80), "label"), (f": {count} {reason.replace('_', ' ')}", "text")))
    rejected = [record for record in review.imports if record.status == "rejected"]
    heading("rejected", len(rejected), "SARIF files nothing was imported from")
    for record in rejected:
        code = record.error or "invalid_sarif"
        lines.append(line(("  ", ""), (clean(record.name, 80), "label"), (f": {code} — ", "muted"),
                          (SARIF_ERRORS.get(code, code.replace("_", " ")), "text")))
    for record in review.imports:
        if record.failed_runs:
            lines.append(line(("  ", ""), (clean(record.name, 80), "label"),
                              (f": {plural(record.failed_runs, 'run')} reported no results or an unsuccessful "
                               "execution; that tool may not have finished.", "warning")))
    lines.append(())
    lines.append(line(("Imported results are untrusted data: they never change Polaris results, coverage or exit codes "
                       "unless --fail-on-imported is set.", "muted")))
    return lines


# ---- the attack surface ------------------------------------------------------------------------------

KIND_LABEL = {
    "route_handler": "route handler", "pages_api": "pages/api route", "server_action": "server action",
    "express_handler": "route (Express-style)", "middleware": "middleware", "page": "page",
}


def guard_state(entry: EntryPoint) -> theme.State:
    if entry.guarded:
        return theme.SURFACE["guarded"]
    if entry.public:
        return theme.SURFACE["public"]
    return theme.SURFACE["unguarded"]


def handler_label(entry: EntryPoint) -> str:
    name = clean(entry.name, 120)
    if entry.kind == "server_action":
        return f"action {name}"
    if entry.kind == "pages_api":
        return "pages/api handler"
    return name


def surface_rows(data: ReviewData, where_width: int = 200) -> list[tuple[str, tuple[Line, Line, Line, Line, Line]]]:
    findings = {finding.finding_id: finding for finding in data.envelope.review.findings}
    rows: list[tuple[str, tuple[Line, Line, Line, Line, Line]]] = []
    for index, entry in enumerate(data.envelope.review.surface):
        linked = [findings[item] for item in entry.findings if item in findings]
        worst = min((finding.severity or "medium" for finding in linked), key=theme.severity_rank, default=None)
        reach: list[Span] = []
        if entry.writes:
            reach.append((f"{len(entry.writes)} write{'s' if len(entry.writes) != 1 else ''} ", "warning"))
        if entry.reads:
            reach.append((f"{len(entry.reads)} read{'s' if len(entry.reads) != 1 else ''} ", "text"))
        if entry.sinks:
            reach.append((f"{entry.sinks} sink{'s' if entry.sinks != 1 else ''}", "muted"))
        state = theme.severity(worst)
        rows.append((f"entry-{index}", (
            line(state_span(guard_state(entry))), line((handler_label(entry), "label")),
            line((tail(where(entry.path, entry.line), where_width), "muted")), line(*reach) or line(("—", "muted")),
            line((f"{len(linked)}{state.glyph}" if linked else "—", state.role if linked else "muted")),
        )))
    return rows


def surface_detail(entry: EntryPoint, data: ReviewData) -> list[Line]:
    findings = {finding.finding_id: finding for finding in data.envelope.review.findings}
    guard = guard_state(entry)
    lines: list[Line] = [
        line(state_span(guard), ("  ", ""), (handler_label(entry), "heading"), (f"  {KIND_LABEL.get(entry.kind, entry.kind)}",
                                                                               "muted")),
        line((where(entry.path, entry.line), "label"), (f"–{entry.end_line}", "muted")), (),
    ]
    if entry.guarded:
        names = ", ".join(clean(name, 80) for name in entry.guards) or "a recognized guard"
        lines.append(line(("Auth guard: ", "label"), (names, "text"), (" (a call was seen; correctness isn't proven)", "muted")))
    else:
        lines.append(line(("Auth guard: ", "label"), ("none found in the handler or its route middleware", "text")))
    if entry.public:
        lines.append(line(("Public route: ", "label"), ("matches [workflow].public_routes in .polaris.toml", "text")))
    if entry.rate_limited:
        lines.append(line(("Rate limited: ", "label"), ("yes", "text")))
    for label, items in (("Writes", entry.writes), ("Reads", entry.reads)):
        if items:
            lines.append(line((f"{label}: ", "label"), (", ".join(f"{clean(item.label, 80)} (line {item.line})"
                                                                for item in items), "text")))
    lines.append(line(("Dangerous calls reached: ", "label"), (str(entry.sinks), "text")))
    lines.append(())
    linked = [findings[item] for item in entry.findings if item in findings]
    if linked:
        lines.append(line((f"Findings inside this handler ({len(linked)}) — press ", "label"), ("enter", "key"),
                          (" to see the first in Findings", "label")))
        for finding in linked:
            lines.append(line(("  ", ""), severity_span(finding.severity, short=True), ("  ", ""),
                              state_span(theme.RESULT.get(finding.result, theme.RESULT["error"])),
                              (f"  {clean(finding.title, 80)} · line {finding.start_line}", "text")))
    else:
        lines.append(line(("No findings inside this handler.", "muted")))
    lines.append(())
    lines.append(line(("Evidence for review, not an access-control model. Python handlers aren't listed yet.", "muted")))
    return lines


def surface_summary(entries: Sequence[EntryPoint]) -> Line:
    unguarded = sum(1 for entry in entries if not entry.guarded and not entry.public)
    public = sum(1 for entry in entries if entry.public and not entry.guarded)
    writes = sum(1 for entry in entries if entry.writes and not entry.guarded and not entry.public)
    return line((plural(len(entries), "entry point"), "label"),
                (f" · {theme.SURFACE['unguarded'].glyph} {unguarded} without an auth guard", "cov.missing" if unguarded else "muted"),
                (f" ({writes} of them write data)" if writes else "", "warning"),
                (f" · {theme.SURFACE['public'].glyph} {public} public by configuration" if public else "", "muted"))
