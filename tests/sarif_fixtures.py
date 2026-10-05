"""Small hand-written SARIF 2.1.0 files shaped like real tools' output (no tool is run).

Each keeps the parts that matter for importing: how the tool names files (absolute file URIs,
`%SRCROOT%`-relative URIs with or without `originalUriBaseIds`, plain relative paths), where
rules live (driver or extensions), levels, tags, CWE references, security-severity, message
links and fingerprints. Snippets and help URIs are present because real tools emit them;
Polaris must never echo them.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

# The checkout a CI job used when it produced the SARIF (another machine than the review).
PRODUCER = "/home/runner/work/app/app"
SECRET_SNIPPET = "SNIPPET-MUST-NOT-LEAK-0123456789"


def dump(document: Any) -> bytes:
    return json.dumps(document).encode("utf-8")


def location(uri: str, line: int | None, *, base: str | None = None, index: int | None = None,
             end: int | None = None, snippet: str | None = None) -> dict[str, Any]:
    artifact: dict[str, Any] = {"uri": uri}
    if base is not None:
        artifact["uriBaseId"] = base
    if index is not None:
        artifact["index"] = index
    physical: dict[str, Any] = {"artifactLocation": artifact}
    if line is not None:
        region: dict[str, Any] = {"startLine": line, "startColumn": 3}
        if end is not None:
            region["endLine"] = end
        if snippet is not None:
            region["snippet"] = {"text": snippet}
        physical["region"] = region
    return {"physicalLocation": physical}


def eslint(root: Path) -> dict[str, Any]:
    """@microsoft/eslint-formatter-sarif: absolute file URIs, rules by index, explicit levels."""
    uri = (root / "api" / "route.ts").as_uri()
    return {
        "version": "2.1.0", "$schema": "http://json.schemastore.org/sarif-2.1.0-rtm.5",
        "runs": [{
            "tool": {"driver": {"name": "ESLint", "informationUri": "https://eslint.org", "version": "9.12.0",
                                "rules": [
                                    {"id": "no-eval", "helpUri": "https://eslint.org/docs/latest/rules/no-eval",
                                     "shortDescription": {"text": "Disallow the use of `eval()`"},
                                     "properties": {"category": "Best Practices"}},
                                    {"id": "no-unused-vars",
                                     "helpUri": "https://eslint.org/docs/latest/rules/no-unused-vars",
                                     "shortDescription": {"text": "Disallow unused variables"}},
                                ]}},
            "artifacts": [{"location": {"uri": uri}}],
            "results": [
                {"level": "error", "message": {"text": "eval can be harmful."}, "ruleId": "no-eval",
                 "ruleIndex": 0, "locations": [location(uri, 6, index=0, end=6)]},
                {"level": "warning", "message": {"text": "'agent' is assigned a value but never used."},
                 "ruleId": "no-unused-vars", "ruleIndex": 1, "locations": [location(uri, 3, index=0)]},
            ],
        }],
    }


def ruff() -> dict[str, Any]:
    """`ruff check --output-format sarif`: absolute file URIs from the producer's checkout, every
    level "error", the linter in rule properties (flake8-bandit codes are security rules)."""
    uri = f"file://{PRODUCER}/app/util.py"
    return {
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "ruff", "informationUri": "https://github.com/astral-sh/ruff",
                                "version": "0.6.9", "rules": [
                                    {"id": "S602", "shortDescription": {
                                        "text": "`subprocess` call with `shell=True` identified, security issue"},
                                     "helpUri": "https://docs.astral.sh/ruff/rules/subprocess-popen-with-shell-equals-true",
                                     "properties": {"id": "S602", "kind": "flake8-bandit",
                                                    "name": "subprocess-popen-with-shell-equals-true",
                                                    "problem.severity": "error"}},
                                    {"id": "E501", "shortDescription": {"text": "Line too long"},
                                     "properties": {"id": "E501", "kind": "pycodestyle", "name": "line-too-long",
                                                    "problem.severity": "error"}},
                                ]}},
            "results": [
                {"level": "error", "ruleId": "S602", "locations": [location(uri, 5, end=5)],
                 "message": {"text": "`subprocess` call with `shell=True` identified, security issue"}},
                {"level": "error", "ruleId": "E501", "locations": [location(uri, 9)],
                 "message": {"text": "Line too long (101 > 88)"}},
            ],
        }],
    }


def codeql() -> dict[str, Any]:
    """CodeQL: rules in a query-pack extension, `%SRCROOT%` declared as the producer's checkout,
    levels from the rule, security-severity, embedded links and partial fingerprints."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {"name": "CodeQL", "organization": "GitHub", "semanticVersion": "2.19.1", "rules": []},
                "extensions": [{"name": "codeql/javascript-queries", "semanticVersion": "1.1.0", "rules": [
                    {"id": "js/request-forgery", "name": "js/request-forgery",
                     "shortDescription": {"text": "Server-side request forgery"},
                     "defaultConfiguration": {"enabled": True, "level": "error"},
                     "properties": {"tags": ["security", "external/cwe/cwe-918"], "kind": "path-problem",
                                    "precision": "high", "security-severity": "9.1", "problem.severity": "error",
                                    "id": "js/request-forgery"}},
                    {"id": "js/unused-local-variable", "name": "js/unused-local-variable",
                     "shortDescription": {"text": "Unused variable, import, function or class"},
                     "defaultConfiguration": {"enabled": True, "level": "note"},
                     "properties": {"tags": ["maintainability", "useless-code", "external/cwe/cwe-563"],
                                    "kind": "problem", "precision": "very-high", "problem.severity": "recommendation"}},
                ]}],
            },
            "originalUriBaseIds": {"%SRCROOT%": {"uri": f"file://{PRODUCER}/"}},
            "artifacts": [{"location": {"uri": "api/route.ts", "uriBaseId": "%SRCROOT%", "index": 0}}],
            "results": [
                {"ruleId": "js/request-forgery",
                 "rule": {"id": "js/request-forgery", "index": 0, "toolComponent": {"index": 0}},
                 "message": {"text": "The [URL](1) of this request depends on a [user-provided value](2)."},
                 "locations": [location("api/route.ts", 7, base="%SRCROOT%", index=0)],
                 "partialFingerprints": {"primaryLocationLineHash": "8c2bd6a7b5f3c9c4:1",
                                         "primaryLocationStartColumnFingerprint": "17"},
                 "relatedLocations": [{"id": 1, "physicalLocation": {"artifactLocation": {
                     "uri": "api/route.ts", "uriBaseId": "%SRCROOT%"}, "region": {"startLine": 7}}}]},
                {"ruleId": "js/unused-local-variable",
                 "rule": {"id": "js/unused-local-variable", "index": 1, "toolComponent": {"index": 0}},
                 "message": {"text": "Unused variable response."},
                 "locations": [location("api/route.ts", 8, base="%SRCROOT%", index=0)],
                 "partialFingerprints": {"primaryLocationLineHash": "11aa22bb33cc44dd:1"}},
            ],
        }],
    }


def semgrep() -> dict[str, Any]:
    """Semgrep: `%SRCROOT%`-relative URIs without declaring the base, no result level (the rule's
    default applies), CWE and OWASP tags, a snippet, match-based fingerprints, and a repeat."""
    rule = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"
    result = {"fingerprints": {"matchBasedId/v1": "0f" * 32}, "ruleId": rule, "properties": {},
              "message": {"text": "Found 'subprocess' function 'run' with 'shell=True'. This is dangerous."},
              "locations": [location("app/util.py", 5, base="%SRCROOT%", end=5,
                                     snippet='    subprocess.run("git log " + branch, shell=True)')]}
    return {
        "version": "2.1.0",
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json",
        "runs": [{
            "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
            "results": [result, dict(result)],
            "tool": {"driver": {"name": "Semgrep OSS", "semanticVersion": "1.95.0", "rules": [{
                "id": rule, "name": rule, "defaultConfiguration": {"level": "error"},
                "helpUri": "https://semgrep.dev/r/" + rule,
                "shortDescription": {"text": "Semgrep Finding: " + rule},
                "properties": {"precision": "very-high", "tags": [
                    "CWE-78: Improper Neutralization of Special Elements used in an OS Command "
                    "('OS Command Injection')", "HIGH CONFIDENCE", "OWASP-A03:2021 - Injection", "security"]},
            }]}},
        }],
    }


def gitleaks() -> dict[str, Any]:
    """Gitleaks: plain relative paths, no levels, empty partial fingerprints and the secret itself
    in the snippet."""
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "gitleaks", "semanticVersion": "v8.21.2",
                                "informationUri": "https://github.com/gitleaks/gitleaks",
                                "rules": [{"id": "generic-api-key", "shortDescription": {
                                    "text": "Detected a Generic API Key, potentially exposing access."}}]}},
            "results": [
                {"message": {"text": "generic-api-key has detected secret for file api/config.ts."},
                 "ruleId": "generic-api-key",
                 "locations": [location("api/config.ts", 2, end=2, snippet=SECRET_SNIPPET)],
                 "partialFingerprints": {"commitSha": "", "email": "", "author": "", "date": "", "commitMessage": ""}},
                {"message": {"text": "generic-api-key has detected secret for file docs/notes.md."},
                 "ruleId": "generic-api-key", "locations": [location("docs/notes.md", 1, snippet=SECRET_SNIPPET)]},
            ],
        }],
    }


def golangci() -> dict[str, Any]:
    """golangci-lint: a language Polaris does not analyze, so only the other tool covers it."""
    return {
        "version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "golangci-lint"}},
            "results": [{"ruleId": "errcheck", "level": "error",
                         "message": {"text": "Error return value of `f.Close` is not checked"},
                         "locations": [location("cmd/main.go", 4)]}],
        }],
    }


def minimal(*results: dict[str, Any], tool: str = "Linter", **run: Any) -> dict[str, Any]:
    """One run of one tool with the given results (for hostile and edge-case inputs)."""
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "results": list(results), **run}]}


def result(uri: str, line: int | None = 3, *, rule: str = "rule-1", text: str = "Something is wrong.",
           **fields: Any) -> dict[str, Any]:
    return {"ruleId": rule, "level": "error", "message": {"text": text}, "locations": [location(uri, line)], **fields}
