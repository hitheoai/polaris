"""CI outputs retain incomplete-analysis signals instead of presenting empty success.

SARIF results carry the source-to-sink trace as a codeFlow, the deterministic suggested edit
as a fix, rule help from the check catalog and a line-independent fingerprint, so code
scanning UIs show the same actionable evidence as the CLI.

Results imported from other tools' SARIF (`--import-sarif`) are re-emitted as separate runs
under their own tool's name, marked as imported and not verified by Polaris, and as Code
Quality issues that say so. They carry no links, snippets or fixes.
"""

from __future__ import annotations

import re
from typing import Any

from polaris import __version__
from polaris.review import catalog
from polaris.review.models import ImportedFinding
from polaris.review.output import CODEQUALITY_SEVERITY, SARIF_LEVEL
from polaris.review.sarif_import import by_tool, corroborations
from polaris.workflow.models import WorkflowEnvelope

SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "1.0"}
FLAGGED_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
CODEQUALITY_LEVEL = {"critical": "blocker", "high": "critical", "medium": "major", "low": "minor", "info": "info"}
# Code Climate / GitLab Code Quality category names.
CODEQUALITY_CATEGORY = {
    "security": "Security", "correctness": "Bug Risk", "reliability": "Bug Risk",
    "performance": "Performance", "maintainability": "Clarity",
}


def _category(check_id: str) -> str:
    return catalog.check_category(check_id) or "security"


def _level(finding: Any) -> str:
    if finding.result == "flagged":
        return FLAGGED_LEVEL.get(finding.severity or "medium", "warning")
    if finding.result == "needs_context":
        return "note"
    return SARIF_LEVEL.get(finding.result, "note")


def _rule_id(finding: Any) -> str:
    return finding.rule_id or f"polaris/{finding.check_id}"


def _cwe_tag(cwe: str | None) -> list[str]:
    match = re.fullmatch(r"CWE-(\d+)", cwe or "")
    return [f"external/cwe/cwe-{match.group(1)}"] if match else []


def _rule(rule_id: str, check_id: str, severity: str | None) -> dict[str, Any]:
    check = catalog.CHECKS.get(check_id)
    info = catalog.RULES.get(rule_id)
    title = (info.title if info else None) or (check.title if check else check_id.replace("_", " "))
    fix = (info.fix if info else None) or (check.fix if check else "")
    why = check.why if check else title
    cwe = (info.cwe if info else None) or (check.cwe if check else None)
    chosen = severity or (info.severity if info else None) or (check.severity if check else "medium")
    markdown = f"**{title}**\n\n{why}\n\n**Fix:** {fix}"
    if check and check.example_bad and check.example_good:
        markdown += f"\n\nInstead of:\n\n```\n{check.example_bad}\n```\n\nPrefer:\n\n```\n{check.example_good}\n```"
    category = _category(check_id)
    properties: dict[str, Any] = {"tags": [category, check_id, *_cwe_tag(cwe)]}
    # Code scanning ranks security-severity only for security rules.
    if category == "security":
        properties["security-severity"] = SECURITY_SEVERITY.get(chosen, "5.5")
    properties["precision"] = "high"
    return {
        "id": rule_id, "name": title, "shortDescription": {"text": title},
        "fullDescription": {"text": why}, "help": {"text": f"{why} Fix: {fix}", "markdown": markdown},
        "properties": properties,
    }


def _physical(path: str, line: int, end_line: int | None = None, snippet: str | None = None) -> dict[str, Any]:
    region: dict[str, Any] = {"startLine": max(1, line)}
    if end_line and end_line >= line:
        region["endLine"] = end_line
    if snippet:
        region["snippet"] = {"text": snippet}
    return {"artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"}, "region": region}


def _flagged_line(finding: Any) -> str | None:
    if not finding.snippet or not finding.snippet_start_line:
        return None
    lines = finding.snippet.splitlines()
    index = finding.start_line - finding.snippet_start_line
    return lines[index] if 0 <= index < len(lines) else None


def _code_flow(finding: Any) -> list[dict[str, Any]]:
    steps = list(finding.trace or [])
    if len(steps) < 2:
        return []
    return [{"threadFlows": [{"locations": [
        {"location": {"physicalLocation": _physical(step.path or finding.path, step.line),
                      "message": {"text": step.label}},
         "kinds": [{"source": "taint", "sink": "danger", "call": "call"}.get(step.kind, "value")]}
        for step in steps
    ]}]}]


def _fixes(finding: Any) -> list[dict[str, Any]]:
    edit = finding.suggested_edit
    if edit is None:
        return []
    return [{
        "description": {"text": edit.note or "Polaris suggested edit; review before applying."},
        "artifactChanges": [{
            "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
            "replacements": [{
                "deletedRegion": {"startLine": edit.line, "startColumn": 1, "endLine": edit.line,
                                  "endColumn": len(edit.original) + 1},
                "insertedContent": {"text": edit.replacement},
            }],
        }],
    }]


def _imported_location(item: ImportedFinding) -> dict[str, Any]:
    physical: dict[str, Any] = {"artifactLocation": {"uri": item.path, "uriBaseId": "%SRCROOT%"}}
    if item.start_line is not None:
        physical["region"] = {"startLine": item.start_line, "endLine": item.end_line or item.start_line}
    return {"physicalLocation": physical}


def _imported_runs(report: WorkflowEnvelope) -> list[dict[str, Any]]:
    """One run per reporting tool, attributed to that tool and marked as not verified by Polaris."""
    runs = []
    for tool, items in by_tool(report.review.imported):
        rules: dict[str, dict[str, Any]] = {}
        indices: dict[str, int] = {}
        results = []
        for item in items:
            rule_id = item.rule_id or "imported-result"
            if rule_id not in rules:
                properties: dict[str, Any] = {
                    "tags": [item.category, *(f"external/cwe/cwe-{cwe[4:]}" for cwe in item.cwe)],
                }
                if item.security_severity is not None:
                    properties["security-severity"] = f"{item.security_severity:.1f}"
                indices[rule_id] = len(rules)
                rules[rule_id] = {"id": rule_id, "shortDescription": {"text": rule_id}, "properties": properties}
            results.append({
                "ruleId": rule_id, "ruleIndex": indices[rule_id], "level": item.level,
                "message": {"text": f"{item.message} [Reported by {tool}; imported by Polaris, not verified.]"},
                "locations": [_imported_location(item)],
                "partialFingerprints": {"polarisImported/v1": item.fingerprint},
                "properties": {
                    "importedBy": "Polaris", "verifiedByPolaris": False, "severity": item.severity,
                    "category": item.category, "cwe": list(item.cwe), "sarifDigest": item.sarif_digest,
                    **({"relatedCheck": item.related_check} if item.related_check else {}),
                    **({"corroborates": item.corroborates} if item.corroborates else {}),
                },
            })
        driver: dict[str, Any] = {"name": tool, "rules": list(rules.values())}
        if items[0].tool_version:
            driver["version"] = items[0].tool_version
        runs.append({
            "tool": {"driver": driver}, "results": results,
            "properties": {"importedBy": "Polaris", "verifiedByPolaris": False},
        })
    return runs


def to_sarif(report: WorkflowEnvelope) -> dict[str, Any]:
    results = []
    rules: dict[str, dict[str, Any]] = {}
    also = corroborations(report.review)
    for finding in report.review.findings:
        if finding.result == "ok":
            continue
        rule_id = _rule_id(finding)
        if rule_id not in rules:
            rules[rule_id] = _rule(rule_id, finding.check_id, finding.severity)
        text = finding.message
        if finding.result == "needs_context" and finding.verify:
            text += f" Verify: {finding.verify}"
        elif finding.guidance:
            text += f" Fix: {finding.guidance}"
        result: dict[str, Any] = {
            "ruleId": rule_id, "ruleIndex": list(rules).index(rule_id), "level": _level(finding),
            "message": {"text": text},
            "locations": [{"physicalLocation": _physical(
                finding.path, finding.start_line, finding.end_line, _flagged_line(finding))}],
            "partialFingerprints": {
                "polarisFinding/v2": finding.finding_id,
                **({"polarisFingerprint/v1": finding.fingerprint} if finding.fingerprint else {}),
            },
            "properties": {
                "result": finding.result, "check": finding.check_id, "severity": finding.severity,
                "category": _category(finding.check_id),
                "confidence": finding.confidence, "cwe": finding.cwe, "symbol": finding.symbol,
                "analyzer": finding.analyzer_id, "analyzerVersion": finding.analyzer_version,
                "evidenceDigest": finding.evidence_digest,
                **({"security-severity": SECURITY_SEVERITY.get(finding.severity or "medium", "5.5")}
                   if _category(finding.check_id) == "security" else {}),
                **({"verify": finding.verify} if finding.verify else {}),
                **({"callSites": list(finding.call_sites)} if finding.call_sites else {}),
                **({"corroboratedBy": [
                    {"tool": item.tool, "ruleId": item.rule_id, "line": item.start_line, "verifiedByPolaris": False}
                    for item in also[finding.finding_id][:8]
                ]} if finding.finding_id in also else {}),
            },
        }
        flows = _code_flow(finding)
        if flows:
            result["codeFlows"] = flows
        fixes = _fixes(finding)
        if fixes:
            result["fixes"] = fixes
        results.append(result)
    incomplete = report.status != "complete"
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Polaris", "semanticVersion": __version__, "organization": "TheoVex",
                "informationUri": "https://polaris.theovex.com", "rules": list(rules.values()),
            }},
            "results": results,
            "invocations": [{
                "executionSuccessful": not incomplete,
                "toolExecutionNotifications": (
                    [{"level": "warning", "message": {"text": report.summary}}] if incomplete else []
                ),
            }],
            "properties": {
                "workflowFormat": report.format, "reportId": report.report_id, "status": report.status,
                "checks": report.review.checks,
                "coverage": report.review.coverage.model_dump(mode="json"),
                "snapshot": report.snapshot.model_dump(mode="json"),
                "behavioralTests": "not_run", "notices": report.notices,
                **({"imports": [item.model_dump(mode="json") for item in report.review.imports]}
                   if report.review.imports else {}),
            },
        }, *_imported_runs(report)],
    }


def to_codequality(report: WorkflowEnvelope) -> list[dict[str, Any]]:
    issues = []
    for finding in report.review.findings:
        if finding.result == "ok":
            continue
        severity = (CODEQUALITY_LEVEL.get(finding.severity or "medium", "major")
                    if finding.result == "flagged" else CODEQUALITY_SEVERITY.get(finding.result, "minor"))
        label = "verify" if finding.result == "needs_context" else finding.result
        issues.append({
            "type": "issue", "check_name": _rule_id(finding),
            "description": f"Polaris {label}: {finding.title} — {finding.message}",
            "categories": [CODEQUALITY_CATEGORY.get(_category(finding.check_id), "Security")], "severity": severity,
            "fingerprint": finding.fingerprint or finding.finding_id,
            "location": {"path": finding.path, "lines": {"begin": finding.start_line, "end": finding.end_line}},
        })
    for item in report.review.imported:
        begin = item.start_line or 1
        issues.append({
            "type": "issue", "check_name": f"{item.tool}/{item.rule_id or 'imported-result'}",
            "description": f"{item.tool} (imported, not verified by Polaris): {item.message}",
            "categories": [CODEQUALITY_CATEGORY.get(item.category, "Bug Risk")],
            "severity": CODEQUALITY_LEVEL.get(item.severity, "minor"), "fingerprint": item.fingerprint,
            "location": {"path": item.path, "lines": {"begin": begin, "end": item.end_line or begin}},
        })
    if report.status != "complete":
        issues.append({
            "type": "issue", "check_name": "polaris/incomplete-review",
            "description": report.summary + " Do not treat this report as clean.",
            "categories": ["Security"], "severity": "major", "fingerprint": report.report_id,
            "location": {"path": report.changes[0].path if report.changes else ".",
                         "lines": {"begin": 1, "end": 1}},
        })
    return issues
