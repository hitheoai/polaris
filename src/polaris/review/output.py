"""Render review reports as readable text or SARIF 2.1.0 (GitHub/GitLab code scanning)."""

from __future__ import annotations

from typing import Any

from polaris import __version__
from polaris.review.models import GUIDANCE, TITLES, Finding, ReviewReport, in_sentence

LABELS = {
    "flagged": "FLAGGED",
    "needs_context": "CONTEXT",
    "uncertain": "UNSURE",
    "too_large": "TOO LONG",
    "error": "ERROR",
    "unsupported": "UNSUPPORTED",
    "ok": "OK",
}
SARIF_LEVEL = {"flagged": "error", "needs_context": "warning", "uncertain": "warning",
               "too_large": "note", "error": "note", "unsupported": "note", "ok": "none"}
SEVERITY = {"sql_injection": "8.8", "command_injection": "9.1"}


def to_text(report: ReviewReport, *, color: bool = False, show_ok: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    tones = {"flagged": "1;31", "needs_context": "33", "uncertain": "33", "error": "35", "too_large": "35"}
    summary = report.summary
    engine = engine_label(report)
    seconds = summary.elapsed_ms / 1000

    def plural(count: int, word: str) -> str:
        return f"{count} {word}" + ("" if count == 1 else "s")

    lines = [
        paint("Polaris review", "1")
        + f" · {engine} · {plural(summary.units_total, 'function')} in {plural(summary.files_reviewed, 'file')}"
        + f" · {seconds:.2f}s"
    ]
    shown = [f for f in report.findings if show_ok or f.result != "ok"]
    for finding in shown:
        label = paint(f"{LABELS[finding.result]:<11}", tones.get(finding.result, "32"))
        where = f"{finding.path}:{finding.start_line}-{finding.end_line}"
        lines.append(f"  {label} {where}  {finding.symbol}  · {finding.title}")
        lines.append(f"              {finding.message}")
        for detail in finding.details[:2]:
            lines.append(f"              - {detail}")
        if finding.guidance and finding.result == "flagged":
            lines.append(f"              Fix: {finding.guidance}")
        if finding.second_opinion is not None:
            lines.append(paint(f"              Model second opinion: {opinion_text(finding)}", "2"))
    if not shown:
        lines.append("  " + paint("No problems found", "32") + " in the reviewed code.")
    extra = second_opinion_only(report)
    if extra and not show_ok:
        lines.append(paint("Second opinion only", "1") + " (the rules found no problem; the Polaris model "
                     "thinks these look risky. Not counted as findings):")
        for finding in extra:
            lines.append(f"  {'MODEL':<11} {finding.path}:{finding.start_line}-{finding.end_line}  "
                         f"{finding.symbol}  · {finding.title} · {opinion_text(finding)}")
    counts = summary.results
    parts = [f"{counts.get(name, 0)} {text}" for name, text in (
        ("flagged", "flagged"), ("needs_context", "need context"), ("uncertain", "unsure"),
        ("too_large", "too long"), ("error", "errors"), ("ok", "look OK"))
        if counts.get(name, 0) or name in ("flagged", "ok")]
    lines.append("Summary: " + " · ".join(parts) + " (one result per function and check)")
    if summary.units_prefiltered:
        lines.append(f"  {summary.units_prefiltered} functions had no SQL or process calls and were skipped instantly.")
    if summary.cache_hits:
        lines.append(f"  {summary.cache_hits} unchanged functions came from the local cache.")
    skipped = ", ".join(f"{count} {reason.replace('_', ' ')}" for reason, count in summary.files_skipped.items())
    if skipped:
        lines.append(f"  Skipped files: {skipped}.")
    for notice in report.notices:
        lines.append(paint(f"  Note: {notice}", "2"))
    return "\n".join(lines) + "\n"


def engine_label(report: ReviewReport) -> str:
    model = report.model
    name = f"{model.model_version or 'unknown'} ({model.release_status})"
    if model.engine == "hybrid":
        return f"rules + second opinion from {name}"
    return f"model {name}" if model.engine == "model" else "rule engine"


def opinion_text(finding: Finding) -> str:
    opinion = finding.second_opinion
    if opinion is None:
        return ""
    words = {"flagged": "likely risky", "ok": "no risk found", "uncertain": "not sure",
             "needs_context": "needs more context", "too_large": "too long to assess",
             "error": "no assessment", "unsupported": "check not supported"}[opinion.result]
    return words + (f" (estimated risk {opinion.risk:.0%})" if opinion.risk is not None else "")


def second_opinion_only(report: ReviewReport) -> list[Finding]:
    """Rule-OK results the model flags (hybrid reviews). Informational; never counted."""
    return [f for f in report.findings
            if f.result == "ok" and f.second_opinion is not None and f.second_opinion.result == "flagged"]


CODEQUALITY_SEVERITY = {"flagged": "critical", "needs_context": "minor", "uncertain": "minor",
                        "too_large": "info", "error": "info", "unsupported": "info"}


def to_codequality(report: ReviewReport) -> list[dict[str, Any]]:
    """GitLab Code Quality report (a subset of the Code Climate format) for merge request widgets."""
    issues = []
    for finding in report.findings:
        if finding.result == "ok":
            continue
        issues.append({
            "type": "issue",
            "check_name": f"polaris/{finding.check_id}",
            "description": f"Polaris {LABELS[finding.result].lower()}: {finding.message} ({finding.symbol})",
            "categories": ["Security"],
            "severity": CODEQUALITY_SEVERITY[finding.result],
            "fingerprint": finding.finding_id,
            "location": {"path": finding.path, "lines": {"begin": finding.start_line, "end": finding.end_line}},
        })
    return issues


def to_sarif(report: ReviewReport) -> dict[str, Any]:
    rules = []
    for check in report.checks:
        rules.append({
            "id": f"polaris/{check}",
            "name": TITLES.get(check, check).replace(" ", ""),
            "shortDescription": {"text": TITLES.get(check, check)},
            "fullDescription": {"text": f"Polaris estimate of {in_sentence(TITLES.get(check, check))} risk in changed "
                                        "Python code."},
            "help": {"text": GUIDANCE.get(check, "Review this code manually.")},
            "properties": {"tags": ["security", "polaris"], "security-severity": SEVERITY.get(check, "5.0")},
        })
    results = []
    extra = {finding.finding_id for finding in second_opinion_only(report)}
    for finding in report.findings:
        if finding.result == "ok" and finding.finding_id not in extra:
            continue
        properties: dict[str, Any] = {"result": finding.result, "engine": finding.engine, "reason": finding.reason}
        if finding.risk is not None:
            properties["risk"] = round(finding.risk, 4)
        if finding.second_opinion is not None:
            properties["secondOpinion"] = finding.second_opinion.model_dump(mode="json")
        if finding.finding_id in extra:
            level = "note"
            text = (f"Second opinion only: the Polaris model thinks this looks risky "
                    f"({opinion_text(finding)}); the static rules found no problem. ({finding.symbol})")
        else:
            level, text = SARIF_LEVEL[finding.result], f"{finding.message} ({finding.symbol})"
        results.append({
            "ruleId": f"polaris/{finding.check_id}",
            "level": level,
            "message": {"text": text},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": finding.start_line, "endLine": finding.end_line},
                }
            }],
            "partialFingerprints": {"polarisFinding/v1": finding.finding_id},
            "properties": properties,
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Polaris",
                "organization": "TheoVex",
                "semanticVersion": __version__,
                "informationUri": "https://polaris.theovex.com",
                "rules": rules,
            }},
            "results": results,
            "properties": {
                "model": report.model.model_dump(mode="json"),
                "notices": report.notices,
            },
        }],
    }
