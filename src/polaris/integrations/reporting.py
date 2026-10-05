"""Compact integration summaries without copied source or arbitrary evidence strings.

Evidence is represented by finding references and locations, not copied snippets. The details
remain available by running `polaris check` (or calling the polaris_check tool).
No test execution or resolved finding is inferred from a static result.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

STATUSES = frozenset({"complete", "incomplete", "stale", "error", "unavailable", "busy", "dirty"})
# Results meaning "this code was not reviewed" (legacy formats); they make a review incomplete.
UNREVIEWED = frozenset({"unsupported", "too_large", "error"})
# Possible issues that depend on code or intent the analyzer can't see: listed to verify.
TO_VERIFY = frozenset({"needs_context", "uncertain"})
GAP_STATUSES = frozenset({"not_checked", "partial", "unsupported", "too_large", "error", "unavailable", "omitted"})
SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
FIXES = {
    "sql_injection": "Use parameterized queries; validate dynamic identifiers.",
    "command_injection": "Use a fixed executable and argument list without a shell; end options with --.",
    "code_injection": "Replace dynamic evaluation with a fixed dispatch table.",
    "xss": "Render as text, or sanitize HTML (e.g. DOMPurify) before inserting it.",
    "ssrf": "Fix the destination host or check it against an allowlist before the request.",
    "open_redirect": "Redirect only to same-site relative paths or allowlisted destinations.",
    "secret_exposure": "Remove the exposed value; rotate a real credential through its owner.",
    "path_traversal": "Validate the resolved path against the authorized workspace.",
    "missing_authorization": "Call the project's auth guard before reading or changing data.",
    "insecure_auth_crypto": "Verify tokens before trusting claims; use strong, salted password hashing.",
    "api_authorization": "Restore the policy-required guard; verify behavior with approved tests.",
    "unsafe_security_configuration": "Restore the secure configuration and verify its intended scope.",
    "workflow_injection": "Pass event data through env: and quote it in the script instead of ${{ }}.",
    "untrusted_checkout": "Don't check out or run pull request code in privileged workflows.",
    "excessive_privileges": "Grant only the token permissions needed; run containers as a non-root user.",
    "unpinned_dependency": "Pin third-party actions to a commit SHA and images to a digest.",
    "unverified_download": "Verify a pinned checksum or signature before running downloaded code.",
}


def label(value: Any, *, limit: int = 160) -> str:
    """Metadata only: escape controls and bound values; never call this on source/evidence text."""
    if not isinstance(value, str):
        return "unknown"
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", "?", value)[:limit]


def problem_summary(status: str, reason: str) -> dict[str, Any]:
    return {
        "status": status if status in STATUSES else "error", "finding_count": 0, "to_verify": 0,
        "findings": [], "unreviewed": [reason], "findings_omitted": 0,
        "tests_status": "not_run", "changes_made": "none_by_hook", "findings_resolved": "not_verified",
        "scope": "Only the requested snapshot and explicitly available checks; not a security guarantee.",
    }


def compact_report(envelope: Mapping[str, Any], *, max_findings: int = 10) -> dict[str, Any]:
    """Normalize the versioned workflow envelope, never trusting a free-text 'all clear' summary."""
    if not 1 <= max_findings <= 50:
        raise ValueError("max_findings must be between 1 and 50")
    if envelope.get("format") != "polaris.workflow/0.1.0":
        return problem_summary("incomplete", "Legacy or unknown review format; expanded coverage is unverified.")
    status = envelope.get("status")
    if status not in ("complete", "incomplete", "stale", "error"):
        return problem_summary("error", "Malformed workflow status; no successful review recorded.")
    review = envelope.get("review")
    if not isinstance(review, Mapping):
        return problem_summary("error", "Workflow review details are missing.")
    findings = review.get("findings")
    if not isinstance(findings, list) or any(not isinstance(item, Mapping) for item in findings):
        return problem_summary("error", "Workflow findings are malformed.")
    summary = problem_summary(status, "")
    summary["unreviewed"] = []
    coverage = review.get("coverage", envelope.get("coverage"))
    if not isinstance(coverage, Mapping) or coverage.get("complete") is not True:
        if status == "complete":
            summary["status"] = "incomplete"
        summary["unreviewed"].append("Analysis coverage is missing or incomplete.")
    if isinstance(coverage, Mapping):
        omissions = coverage.get("omissions", [])
        if omissions:
            if summary["status"] == "complete":
                summary["status"] = "incomplete"
            summary["unreviewed"].append("Coverage omissions are present; inspect detailed workflow output.")
        entries = coverage.get("entries")
        if isinstance(entries, list):
            reported: set[str] = set()
            for entry in entries:
                # Documentation/assets are not_applicable and advisory rows are not required.
                if (not isinstance(entry, Mapping) or entry.get("status") not in GAP_STATUSES
                        or entry.get("required", True) is not True):
                    continue
                if summary["status"] == "complete":
                    summary["status"] = "incomplete"
                path = label(entry.get("path"))
                if path not in reported:
                    reported.add(path)
                    summary["unreviewed"].append(
                        f"{path}: {label(entry.get('reason', entry.get('status')), limit=80)}"
                    )
    shown: list[dict[str, Any]] = []
    unresolved = 0
    for finding in findings:
        result = finding.get("result")
        if result == "ok":
            continue
        if result not in UNREVIEWED | TO_VERIFY | {"flagged"}:
            summary["status"] = "error"
            summary["unreviewed"].append("Unknown finding status; no successful review recorded.")
            continue
        unresolved += 1
        if result == "flagged":
            summary["finding_count"] += 1
        elif result in TO_VERIFY:
            summary["to_verify"] += 1
        elif summary["status"] == "complete":
            summary["status"] = "incomplete"
        if len(shown) >= max_findings:
            continue
        check = label(finding.get("check_id"), limit=80)
        line = finding.get("start_line")
        severity = finding.get("severity")
        shown.append({
            "path": label(finding.get("path")), "line": line if type(line) is int and line > 0 else None,
            "check": check, "result": result,
            "severity": severity if severity in SEVERITIES else None,
            "evidence_ref": label(finding.get("finding_id"), limit=80),
            "proposed_fix": FIXES.get(check, "Inspect the finding and propose a narrowly scoped correction."),
            "verification": "static_evidence_only; tests_not_run",
        })
    declared_count = envelope.get("finding_count")
    if type(declared_count) is not int or declared_count != summary["finding_count"]:
        summary["status"] = "error"
        summary["unreviewed"].append("Workflow finding counts disagree; inspect the full result.")
    summary["findings"] = shown
    summary["findings_omitted"] = max(0, unresolved - len(shown))
    if summary["status"] != "complete" and not summary["unreviewed"]:
        summary["unreviewed"].append("Review is not complete; inspect detailed workflow output.")
    if len(summary["unreviewed"]) > 10:
        remaining = len(summary["unreviewed"]) - 10
        summary["unreviewed"] = [*summary["unreviewed"][:10], f"{remaining} more unreviewed scope entries."]
    return summary


def render_summary(summary: Mapping[str, Any]) -> str:
    count = summary.get("finding_count", 0)
    verify = summary.get("to_verify", 0)
    status = summary.get("status", "unavailable")
    lines = [
        f"Polaris review: {status}; {count} issue{'s' if count != 1 else ''} found"
        + (f", {verify} to verify" if verify else "")
        + ". Tests not run; no code or configuration was changed by this hook."
    ]
    for finding in summary.get("findings", []):
        kind = "verify" if finding["result"] in TO_VERIFY else finding["result"]
        severity = f"{finding['severity']} " if finding.get("severity") else ""
        lines.append(
            f"- {finding['path']}:{finding['line'] or '?'} [{severity}{kind}] {finding['check']}; "
            f"evidence {finding['evidence_ref']}. Proposed fix: {finding['proposed_fix']}"
        )
    for omission in summary.get("unreviewed", []):
        if omission:
            lines.append(f"- Unreviewed: {omission}")
    if summary.get("findings_omitted"):
        lines.append(f"- {summary['findings_omitted']} more findings in detailed workflow output.")
    lines.append("Run `polaris check` for details. No claim of finding every possible issue.")
    return "\n".join(lines)
