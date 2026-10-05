"""Turn analyzer facts into findings an engineer or agent can act on immediately.

Every finding carries the exact location, a short snippet, the source-to-sink trace and a
pattern-specific fix. Snippets are bounded, credential-looking values are masked, and
`evidence="redacted"` drops snippets entirely for hosted/API use.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence

from polaris.jsonio import digest_json, digest_text
from polaris.review import catalog
from polaris.review.models import (
    Confidence,
    Severity,
    SourceFile,
    SuggestedEdit,
    TraceStep,
    WorkflowFinding,
)
from polaris.review.secrets import mask, redact

MAX_SNIPPET_LINES = 9
MAX_LINE_CHARS = 220
MAX_LABEL = 200


def lines_of(text: str | None) -> list[str]:
    return text.splitlines() if text else []


def line_text(text: str | None, line: int) -> str:
    lines = lines_of(text)
    return lines[line - 1] if 1 <= line <= len(lines) else ""


def short(text: str, limit: int = MAX_LABEL) -> str:
    collapsed = re.sub(r"\s+", " ", text).strip()
    collapsed = redact(collapsed)
    return collapsed if len(collapsed) <= limit else collapsed[: limit - 1] + "…"


def snippet(text: str | None, start: int, end: int, *, context: int = 2) -> tuple[str | None, int | None]:
    """The flagged lines with a little context, bounded and with credentials masked."""
    lines = lines_of(text)
    if not lines or start < 1 or start > len(lines):
        return None, None
    end = max(start, min(end, len(lines), start + MAX_SNIPPET_LINES - 1))
    first = max(1, start - context)
    last = min(len(lines), end + context, first + MAX_SNIPPET_LINES - 1)
    chosen = []
    for value in lines[first - 1:last]:
        value = value.rstrip()
        chosen.append(value if len(value) <= MAX_LINE_CHARS else value[: MAX_LINE_CHARS - 1] + "…")
    return redact("\n".join(chosen)), first


def fingerprint(path: str, check_id: str, rule_id: str, symbol: str, sink_text: str) -> str:
    """Stable across unrelated edits: no line numbers or whole-file digests."""
    normalized = re.sub(r"\s+", "", sink_text)[:300]
    material = "\0".join((path, check_id, rule_id, symbol, normalized))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def make_finding(
    *, analyzer_id: str, analyzer_version: str, source: SourceFile, check_id: str, rule_id: str,
    result: str, start_line: int, end_line: int | None = None, symbol: str = "<module>",
    message: str, guidance: str | None = None, reason: str = "rule_match",
    severity: Severity | None = None, confidence: Confidence | None = None,
    trace: Sequence[TraceStep] = (), details: Sequence[str] = (),
    suggested_edit: SuggestedEdit | None = None, verify: str | None = None,
    call_sites: Sequence[str] = (), evidence: str = "full",
) -> WorkflowFinding:
    text = source.after or ""
    end = end_line if end_line is not None and end_line >= start_line else start_line
    rule_info = catalog.RULES.get(rule_id)
    chosen_severity: Severity = (
        severity or (rule_info.severity if rule_info and rule_info.severity else None)
        or catalog.default_severity(check_id)
    )
    if result == "needs_context" and catalog.SEVERITY_ORDER[chosen_severity] < catalog.SEVERITY_ORDER["medium"]:
        chosen_severity = "medium"
    shown, shown_start = snippet(text, start_line, end) if evidence == "full" else (None, None)
    sink_text = line_text(text, start_line)
    digest = digest_text(text)
    return WorkflowFinding(
        finding_id=digest_json([analyzer_version, source.path, symbol, digest, check_id, rule_id, start_line])[7:27],
        path=source.path, start_line=start_line, end_line=end, symbol=symbol[:200] or "<module>",
        check_id=check_id, title=catalog.check_title(check_id), result=result,  # type: ignore[arg-type]
        engine="rules", reason=reason, message=short(message, 600),
        guidance=(guidance or (rule_info.fix if rule_info else None) or catalog.CHECKS[check_id].fix)
        if result != "ok" else None,
        details=[short(item, 300) for item in details][:6],
        analyzer_id=analyzer_id, analyzer_version=analyzer_version, rule_id=rule_id,
        evidence_digest=digest, severity=chosen_severity,
        confidence=confidence or ("high" if result == "flagged" else "low"),
        cwe=(rule_info.cwe if rule_info and rule_info.cwe else catalog.check_cwe(check_id)),
        category=catalog.check_category(check_id),
        fingerprint=fingerprint(source.path, check_id, rule_id, symbol, sink_text),
        snippet=shown, snippet_start_line=shown_start,
        trace=[step for step in trace][:16],
        suggested_edit=suggested_edit, verify=short(verify, 900) if verify else None,
        call_sites=[site for site in call_sites][:16],
    )


def mask_values(finding: WorkflowFinding, values: set[str]) -> WorkflowFinding:
    """Mask credentials an analyzer found in this file wherever a finding's snippet quotes them.

    `redact` recognizes token formats and quoted assignments; configuration files (YAML,
    Dockerfiles) usually leave values unquoted, so their analyzers pass the exact values.
    """
    if not values or not finding.snippet:
        return finding
    snippet = finding.snippet
    for value in sorted(values, key=len, reverse=True):
        snippet = snippet.replace(value, mask(value))
    return finding if snippet == finding.snippet else finding.model_copy(update={"snippet": snippet})


def step(kind: str, line: int, label: str, path: str | None = None) -> TraceStep:
    return TraceStep(kind=kind, line=max(1, line), label=short(label or "value", 200) or "value",  # type: ignore[arg-type]
                     path=path)


def insert_edit(source: SourceFile, line: int, column: int, insertion: str, note: str) -> SuggestedEdit | None:
    """Insert text at a 0-based column of one line, when that line is unambiguous."""
    original = line_text(source.after, line)
    if not original or column < 0 or column > len(original) or len(original) > 1_500:
        return None
    return SuggestedEdit(line=line, original=original, replacement=original[:column] + insertion + original[column:],
                         note=note)


def replace_edit(source: SourceFile, line: int, old: str, new: str, note: str) -> SuggestedEdit | None:
    original = line_text(source.after, line)
    if not original or original.count(old) != 1 or len(original) > 1_500:
        return None
    return SuggestedEdit(line=line, original=original, replacement=original.replace(old, new), note=note)
