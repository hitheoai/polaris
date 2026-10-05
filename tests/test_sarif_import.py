"""Other tools' SARIF merged into reviews and pull-request plans as untrusted, labeled data.

The SARIF files are small hand-written copies of real tools' output (tests/sarif_fixtures.py).
Fixture repositories are isolated; nothing is fetched, run, or published to a real forge.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
import sarif_fixtures as fx
from pydantic import ValidationError
from test_forge_github import FakeGitHub, comment, make_plan
from test_forge_github import run as publish_plan

from polaris import cli
from polaris.integrations.forge import markdown
from polaris.integrations.forge.models import PlanCounts, PlannedComment, ReviewPlan
from polaris.integrations.forge.plan import render_imported_comment
from polaris.review import sarif_import
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import ImportedFinding, SarifImport, SourceFile, WorkflowReviewReport
from polaris.review.sarif_import import (
    SarifInput,
    corroborations,
    import_sarif,
    imported_key,
    tool_tag,
    unevaluated,
)
from polaris.workflow.output import to_codequality, to_sarif
from polaris.workflow.service import render_workflow, review_supplied, review_workspace_detailed

MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
ROUTE = '''import https from "https";

export const agent = new https.Agent({ rejectUnauthorized: false });

export async function GET(request: Request) {
  const target = new URL(request.url).searchParams.get("target");
  const response = await fetch(target!);
  return new Response(await response.text());
}
'''
UTIL = '''import subprocess


def run_branch(branch):
    subprocess.run("git log " + branch, shell=True)
'''
TOOLS = ("eslint", "ruff", "codeql", "semgrep", "gitleaks", "golangci")


def fixture_git(root: Path, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin", "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(["git", "--no-pager", "-C", str(root), *args],
                          check=True, capture_output=True, env=env).stdout.decode("utf-8").strip()


@pytest.fixture
def change(tmp_path: Path) -> tuple[Path, str, str]:
    """A pull-request commit touching TypeScript, Python, a config module and a Go file."""
    root = tmp_path.resolve() / "repository"
    for folder in ("api", "app", "cmd"):
        (root / folder).mkdir(parents=True)
    fixture_git(root, "init", "-q", "-b", "main")
    (root / "app" / "util.py").write_text(UTIL)
    (root / "api" / "route.ts").write_text("export const ok = 1;\n")
    (root / "api" / "config.ts").write_text("export const mode = 1;\n")
    (root / "cmd" / "main.go").write_text("package main\n")
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "base")
    base = fixture_git(root, "rev-parse", "HEAD")
    (root / "api" / "route.ts").write_text(ROUTE)
    with (root / "app" / "util.py").open("a") as stream:
        stream.write('\n\ndef greeting(name):\n    return "hello " + name\n')
    (root / "api" / "config.ts").write_text("export const mode = 1;\nexport const token = process.env.TOKEN;\n")
    (root / "cmd" / "main.go").write_text("package main\n\nfunc main() {\n\tf.Close()\n}\n")
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "change")
    return root, base, fixture_git(root, "rev-parse", "HEAD")


def documents(root: Path) -> dict[str, dict[str, Any]]:
    return {"eslint": fx.eslint(root), "ruff": fx.ruff(), "codeql": fx.codeql(), "semgrep": fx.semgrep(),
            "gitleaks": fx.gitleaks(), "golangci": fx.golangci()}


def tool_inputs(root: Path, names: tuple[str, ...] = TOOLS) -> list[SarifInput]:
    return [SarifInput(f"{name}.sarif", data=fx.dump(documents(root)[name])) for name in names]


def write_sarif(directory: Path, root: Path, names: tuple[str, ...] = TOOLS) -> list[str]:
    directory.mkdir(exist_ok=True)
    paths = []
    for name in names:
        path = directory / f"{name}.sarif"
        path.write_bytes(fx.dump(documents(root)[name]))
        paths.append(str(path))
    return paths


SOURCES = [
    SourceFile("src/app.ts", "export const x = 1;\nexport const y = 2;\nexport const z = 3;\n"),
    SourceFile("lib/util.ts", "export const util = 1;\n"),
    SourceFile("index.ts", "export const index = 1;\n"),
    SourceFile("pkg/src/app.ts", "export const nested = 1;\n"),
]
ROOT = Path("/work/repo")


def merge(*inputs: bytes | dict[str, Any] | SarifInput, sources: list[SourceFile] = SOURCES,
          root: Path = ROOT) -> WorkflowReviewReport:
    """Import SARIF into an in-memory review of `sources` (memory-only, nothing executed)."""
    report = review_supplied(sources).review
    chosen = [item if isinstance(item, SarifInput) else
              SarifInput(f"input-{index}.sarif", data=item if isinstance(item, bytes) else fx.dump(item))
              for index, item in enumerate(inputs)]
    return import_sarif(report, chosen, root=root, sources=sources)


def only(report: WorkflowReviewReport) -> SarifImport:
    (record,) = report.imports
    return record


# ---- real-world shapes ---------------------------------------------------------------------------


def test_real_world_sarif_shapes_are_mapped_labeled_and_categorized(change):
    root, base, head = change
    plain = review_workspace_detailed(root, revision_range=f"{base}...{head}", runtime=MEMORY).envelope
    envelope = review_workspace_detailed(root, revision_range=f"{base}...{head}", runtime=MEMORY,
                                         imports=tool_inputs(root)).envelope
    report = envelope.review
    found = {(item.tool, item.rule_id): item for item in report.imported}
    assert {key: (item.path, item.start_line) for key, item in found.items()} == {
        ("ESLint", "no-eval"): ("api/route.ts", 6),  # absolute file URIs of this checkout
        ("ESLint", "no-unused-vars"): ("api/route.ts", 3),
        ("ruff", "S602"): ("app/util.py", 5),  # absolute URIs of another checkout: one root, unanimous
        ("ruff", "E501"): ("app/util.py", 9),
        ("CodeQL", "js/request-forgery"): ("api/route.ts", 7),  # %SRCROOT% declared as that checkout
        ("CodeQL", "js/unused-local-variable"): ("api/route.ts", 8),
        ("Semgrep OSS", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"): ("app/util.py", 5),
        ("gitleaks", "generic-api-key"): ("api/config.ts", 2),
        ("golangci-lint", "errcheck"): ("cmd/main.go", 4),  # a language Polaris does not analyze
    }
    facts = {key: (item.level, item.severity, item.category, item.related_check) for key, item in found.items()}
    assert facts[("ESLint", "no-eval")] == ("error", "medium", "security", "code_injection")
    assert facts[("ESLint", "no-unused-vars")] == ("warning", "low", "correctness", None)
    assert facts[("ruff", "S602")] == ("error", "medium", "security", "command_injection")
    assert facts[("ruff", "E501")] == ("error", "medium", "maintainability", None)
    assert facts[("CodeQL", "js/request-forgery")] == ("error", "critical", "security", "ssrf")
    # An explicit category tag wins over a CWE tag that is not about security.
    assert facts[("CodeQL", "js/unused-local-variable")] == ("note", "info", "maintainability", None)
    assert facts[("gitleaks", "generic-api-key")] == ("warning", "low", "security", "secret_exposure")
    assert facts[("golangci-lint", "errcheck")] == ("error", "medium", "correctness", None)
    forgery = found[("CodeQL", "js/request-forgery")]
    assert forgery.security_severity == 9.1 and forgery.cwe == ["CWE-918"] and forgery.tool_version == "2.19.1"
    assert forgery.message == "The URL of this request depends on a user-provided value."  # links removed
    assert all(item.verified_by_polaris is False for item in report.imported)
    # Polaris's own results, coverage and status never change.
    assert report.findings == plain.review.findings and report.coverage == plain.review.coverage
    assert report.summary.model_dump(exclude={"elapsed_ms"}) == plain.review.summary.model_dump(exclude={"elapsed_ms"})
    assert (envelope.status, envelope.finding_count) == (plain.status, plain.finding_count)
    assert envelope.exit_code() == plain.exit_code() and envelope.exit_code(require_complete=True) == plain.exit_code(
        require_complete=True)
    # Each file is accounted for, and its content is bound into provenance.
    records = {record.name: record for record in report.imports}
    assert all(record.status == "imported" for record in records.values())
    assert records["semgrep.sarif"].dropped == {"duplicate": 1}
    assert records["gitleaks.sarif"].dropped == {"outside_review_scope": 1}
    assert (records["codeql.sarif"].imported, records["codeql.sarif"].corroborating) == (2, 1)
    assert report.provenance.imported_digests == [record.digest for record in report.imports]
    assert report.provenance.imported_digests == sorted(report.provenance.imported_digests)
    assert {item.sarif_digest for item in report.imported} <= set(report.provenance.imported_digests)
    assert plain.review.provenance.imported_digests == [] and plain.review.imported == []
    # Snippets (here a secret) and help links are never kept or echoed.
    outputs = (envelope.model_dump_json() + render_workflow(envelope) + json.dumps(to_sarif(envelope))
               + json.dumps(to_codequality(envelope)))
    for leaked in (fx.SECRET_SNIPPET, "semgrep.dev/r", "eslint.org/docs", "docs.astral.sh", fx.PRODUCER):
        assert leaked not in outputs


def test_corroborating_results_are_shown_with_the_polaris_finding_which_never_changes(change):
    root, base, head = change
    envelope = review_workspace_detailed(root, revision_range=f"{base}...{head}", runtime=MEMORY,
                                         imports=tool_inputs(root)).envelope
    report = envelope.review
    by_check = {finding.check_id: finding for finding in report.findings}
    attached = corroborations(report)
    assert [(item.tool, item.rule_id) for item in attached[by_check["ssrf"].finding_id]] == [
        ("CodeQL", "js/request-forgery")]
    assert sorted(item.tool for item in attached[by_check["command_injection"].finding_id]) == ["Semgrep OSS", "ruff"]
    assert by_check["unsafe_security_configuration"].finding_id not in attached
    text = render_workflow(envelope)
    assert "Also reported by: CodeQL js/request-forgery (line 7) — imported SARIF, not verified by Polaris" in text
    assert "Other tools (6 results) — imported SARIF, not verified by Polaris; 3 more corroborate" in text
    assert "ERROR · errcheck · cmd/main.go:4 · correctness — Error return value" in text
    sarif = to_sarif(envelope)
    polaris, *others = sarif["runs"]
    assert polaris["tool"]["driver"]["name"] == "Polaris" and polaris["properties"]["imports"]
    ssrf = next(item for item in polaris["results"] if item["properties"]["check"] == "ssrf")
    assert ssrf["properties"]["corroboratedBy"] == [
        {"tool": "CodeQL", "ruleId": "js/request-forgery", "line": 7, "verifiedByPolaris": False}]
    assert {run["tool"]["driver"]["name"] for run in others} == {
        "ESLint", "ruff", "CodeQL", "Semgrep OSS", "gitleaks", "golangci-lint"}
    for run in others:
        assert run["properties"] == {"importedBy": "Polaris", "verifiedByPolaris": False}
        for result in run["results"]:
            rule = run["tool"]["driver"]["rules"][result["ruleIndex"]]
            assert rule["id"] == result["ruleId"] and "helpUri" not in rule
            assert result["message"]["text"].endswith("imported by Polaris, not verified.]")
            assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] == "%SRCROOT%"
    codeql = next(run for run in others if run["tool"]["driver"]["name"] == "CodeQL")
    rules = {rule["id"]: rule for rule in codeql["tool"]["driver"]["rules"]}
    assert rules["js/request-forgery"]["properties"] == {
        "tags": ["security", "external/cwe/cwe-918"], "security-severity": "9.1"}
    quality = [issue for issue in to_codequality(envelope) if "imported" in issue["description"]]
    assert len(quality) == len(report.imported)
    errcheck = next(issue for issue in quality if issue["check_name"] == "golangci-lint/errcheck")
    assert errcheck["description"].startswith("golangci-lint (imported, not verified by Polaris): ")
    assert errcheck["categories"] == ["Bug Risk"] and errcheck["severity"] == "major"
    assert errcheck["location"] == {"path": "cmd/main.go", "lines": {"begin": 4, "end": 4}}


def test_the_same_files_give_the_same_imports_in_any_order(change):
    root, base, head = change

    def imported(names: tuple[str, ...]) -> WorkflowReviewReport:
        return review_workspace_detailed(root, revision_range=f"{base}...{head}", runtime=MEMORY,
                                         imports=tool_inputs(root, names)).envelope.review

    forward, backward = imported(TOOLS), imported(tuple(reversed(TOOLS)))
    assert forward.imported == backward.imported and forward.imports == backward.imports
    assert forward.provenance.imported_digests == backward.provenance.imported_digests
    fewer = imported(TOOLS[:-1])
    assert fewer.provenance.imported_digests != forward.provenance.imported_digests
    assert len(fewer.imported) == len(forward.imported) - 1


# ---- hostile and malformed input -------------------------------------------------------------


CANARY = "CANARY-CONTENT-7f3a"
TEXT = CANARY.encode()


@pytest.mark.parametrize("data,code", [
    (b'{"version": "2.1.0", "runs": ["' + TEXT, "invalid_sarif"),  # truncated
    (b'\xff\xfe{"x": "' + TEXT + b'"}', "invalid_sarif"),  # not UTF-8
    (b'["' + TEXT + b'"]', "invalid_sarif"),  # not an object
    (b"[" * 100_000, "invalid_sarif"),  # nesting past the parser's limit
    (b'{"version": "2.1.0", "version": "2.1.0", "runs": [], "x": "' + TEXT + b'"}', "invalid_sarif"),
    (b'{"version": "2.1.0", "runs": [], "x": NaN, "y": "' + TEXT + b'"}', "invalid_sarif"),
    (b'{"version": "2.0.0", "runs": [], "x": "' + TEXT + b'"}', "unsupported_sarif_version"),
    (b'{"version": 2.1, "runs": []}', "invalid_sarif"),
    (b'{"version": "2.1.0", "runs": {"x": "' + TEXT + b'"}}', "invalid_sarif"),
    (b'{"version": "2.1.0", "runs": [{"tool": {"driver": {"version": "' + TEXT + b'"}}}]}', "invalid_sarif"),
])
def test_malformed_files_are_rejected_whole_with_fixed_codes(data, code):
    report = merge(data)
    record = only(report)
    assert (record.status, record.error, record.imported) == ("rejected", code, 0)
    assert record.digest is not None and report.imported == []
    assert CANARY not in report.model_dump_json()
    assert any(f"rejected and nothing was imported from them: {code} (1)" in notice for notice in report.notices)


@pytest.mark.parametrize("broken", [
    {"level": 5}, {"level": "fatal"}, {"kind": "bogus"}, {"baselineState": "gone"}, {"message": {}},
    {"message": "text"}, {"locations": {}}, {"ruleId": 7}, {"suppressions": [{"kind": "inSource", "status": "maybe"}]},
    {"partialFingerprints": {"hash": 1}}, {"properties": {"tags": "security"}},
    {"locations": [{"physicalLocation": {"artifactLocation": {"uri": 3}}}]},
    {"locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.ts"}, "region": {"startLine": "3"}}}]},
    {"rule": {"index": 0, "toolComponent": {"index": 4}}},
])
def test_one_malformed_result_rejects_the_whole_file(broken):
    report = merge(fx.minimal(fx.result("src/app.ts"), {**fx.result("src/app.ts", 2, text=CANARY), **broken}))
    assert (only(report).status, only(report).error) == ("rejected", "invalid_sarif")
    assert report.imported == [] and CANARY not in report.model_dump_json()


def test_size_structure_and_count_limits_fail_closed(monkeypatch):
    big = fx.minimal(*(fx.result("src/app.ts", line, text=f"result {line}") for line in range(1, 4)))
    monkeypatch.setattr(sarif_import, "MAX_SARIF_BYTES", 200)
    assert only(merge(big)).error == "sarif_too_large"
    monkeypatch.undo()
    monkeypatch.setattr(sarif_import, "MAX_JSON_NODES", 20)
    assert only(merge(big)).error == "sarif_too_large"
    monkeypatch.undo()
    monkeypatch.setattr(sarif_import, "MAX_RUNS", 1)
    assert only(merge({"version": "2.1.0", "runs": big["runs"] * 2})).error == "sarif_too_large"
    monkeypatch.undo()
    monkeypatch.setattr(sarif_import, "MAX_TOTAL_SARIF_BYTES", len(fx.dump(big)) + 10)
    together = merge(SarifInput("a.sarif", data=fx.dump(big)), SarifInput("b.sarif", data=fx.dump(fx.minimal())))
    assert sorted((record.status, record.error) for record in together.imports) == [
        ("imported", None), ("rejected", "sarif_total_limit")]
    monkeypatch.undo()
    # Results past a limit are counted, never silently dropped, and leave an opted-in gate unable to decide.
    monkeypatch.setattr(sarif_import, "MAX_RESULTS_PER_FILE", 2)
    capped = merge(big)
    assert only(capped).dropped == {"result_limit": 1} and len(capped.imported) == 2 and unevaluated(capped)
    monkeypatch.undo()
    monkeypatch.setattr(sarif_import, "MAX_IMPORTED_RESULTS", 1)
    mixed = merge(fx.minimal(fx.result("src/app.ts", 1, level="note"), fx.result("src/app.ts", 2, rule="worse")))
    assert [item.rule_id for item in mixed.imported] == ["worse"], "the most severe results are kept"
    assert only(mixed).dropped == {"imported_limit": 1} and unevaluated(mixed)
    with pytest.raises(sarif_import.SarifProblem, match="too_many_sarif_files"):
        merge(*([fx.minimal()] * 17))


def test_untrusted_locations_never_escape_the_repository():
    local = f"file://{ROOT}/src/app.ts"
    cases = {
        "src/app.ts": "src/app.ts", "./src/app.ts": "src/app.ts", "src/./sub/../app.ts": "src/app.ts",
        local: "src/app.ts", "src/missing.ts": "outside_review_scope",
        "../../etc/passwd": "outside_repository", "src/../../etc/passwd": "outside_repository",
        "%2e%2e/%2e%2e/etc/passwd": "outside_repository", "file:///etc/passwd": "outside_repository",
        "https://evil.example/src/app.ts": "outside_repository", "file://server/share/src/app.ts": "outside_repository",
        "//server/src/app.ts": "outside_repository", "src\\app.ts": "invalid_path", "src/app.ts?x=1": "invalid_path",
        "src/app.ts#L3": "invalid_path", "src/%00app.ts": "invalid_path", "src/\u202eapp.ts": "invalid_path",
        "src/": "invalid_path", "": "invalid_path", "src/a:b.ts": "invalid_path", "%ff.ts": "invalid_path",
    }
    for uri, expected in cases.items():
        report = merge(fx.minimal(fx.result(uri), fx.result(local, 1, rule="anchor")))
        kept = {item.path for item in report.imported if item.rule_id == "rule-1"}
        if "/" in expected or expected.endswith(".ts"):
            assert kept == {expected}, uri
        else:
            assert kept == set() and only(report).dropped == {expected: 1}, uri
    # Base identifiers: undefined bases are the repository root; chains resolve; cycles never do.
    bases = {"PKG": {"uri": "src/", "uriBaseId": "UNDEFINED"}, "A": {"uri": "x/", "uriBaseId": "B"},
             "B": {"uri": "y/", "uriBaseId": "A"}}
    report = merge(fx.minimal(
        {**fx.result("app.ts"), "locations": [fx.location("app.ts", 3, base="PKG")]},
        {**fx.result("app.ts", rule="cycle"), "locations": [fx.location("app.ts", 3, base="A")]},
        {**fx.result("src/app.ts", rule="srcroot"), "locations": [fx.location("src/app.ts", 2, base="%SRCROOT%")]},
        originalUriBaseIds=bases))
    assert sorted((item.rule_id, item.path) for item in report.imported) == [
        ("rule-1", "src/app.ts"), ("srcroot", "src/app.ts")]
    assert only(report).dropped == {"invalid_path": 1}
    # Artifact indexes are followed; a result without a usable location is counted.
    report = merge(fx.minimal(
        {"ruleId": "indexed", "message": {"text": "x"}, "locations": [{"physicalLocation": {
            "artifactLocation": {"index": 0}, "region": {"startLine": 2}}}]},
        {"ruleId": "nowhere", "message": {"text": "x"}},
        {"ruleId": "logical", "message": {"text": "x"}, "locations": [{"logicalLocations": [{"name": "f"}]}]},
        artifacts=[{"location": {"uri": "lib/util.ts"}}]))
    assert [(item.rule_id, item.path) for item in report.imported] == [("indexed", "lib/util.ts")]
    assert only(report).dropped == {"no_location": 2}


def test_another_checkouts_root_is_inferred_only_when_unanimous():
    def mapped(*uris: str) -> list[tuple[str, str | None]]:
        report = merge(fx.minimal(*(fx.result(uri, rule=f"r{index}") for index, uri in enumerate(uris))))
        paths = {item.rule_id: item.path for item in report.imported}
        return [(uri, paths.get(f"r{index}")) for index, uri in enumerate(uris)]

    # Every path that matches names the same root, so even a top-level file maps under it.
    assert mapped("file:///ci/w/src/app.ts", "file:///ci/w/lib/util.ts", "file:///ci/w/index.ts") == [
        ("file:///ci/w/src/app.ts", "src/app.ts"), ("file:///ci/w/lib/util.ts", "lib/util.ts"),
        ("file:///ci/w/index.ts", "index.ts")]
    # Two roots disagree: nothing is guessed.
    assert [path for _, path in mapped("file:///ci/w/src/app.ts", "file:///other/x/lib/util.ts")] == [None, None]
    # A bare file name never identifies a file.
    assert mapped("file:///ci/w/index.ts") == [("file:///ci/w/index.ts", None)]
    # A path with two in-scope candidates stays unmapped even when the rest of the run agrees.
    assert mapped("file:///ci/w/pkg/src/app.ts", "file:///ci/w/lib/util.ts") == [
        ("file:///ci/w/pkg/src/app.ts", None), ("file:///ci/w/lib/util.ts", "lib/util.ts")]
    # Windows drive letters, with or without the file scheme.
    assert [path for _, path in mapped("C:/w/src/app.ts", "file:///C:/w/lib/util.ts")] == ["src/app.ts", "lib/util.ts"]
    report = merge(fx.minimal(fx.result("file:///ci/w/index.ts")))
    assert only(report).dropped == {"unmapped_path": 1}


def test_text_is_bounded_printable_and_rendered_inert():
    marker = "<!-- polaris:finding v1 key=" + "a" * 24 + " state=open -->"
    hostile = (f"{marker} @octocat <img src=x onerror=alert(1)> [click](https://evil.example) "
               "\u202egnp.exe \x1b[31mred\x1b[0m \U000e0041hidden " + "x" * 5_000)
    data = fx.dump(fx.minimal(fx.result("src/app.ts", text=hostile, rule="rule\n" + marker),
                              tool="Evil\u200b<script>@admin")).replace(b"hidden", b"\\ud800")
    report = merge(data)
    (item,) = report.imported
    for text in (item.message, item.rule_id or "", item.tool):
        assert not any(char in text for char in ("\x1b", "\u202e", "\u200b", "\U000e0041", "\ud800", "\n"))
    assert len(item.message) == 1_000 and item.message.endswith("…") and "\ufffd" in item.message
    assert "click" in item.message and "https://evil.example" not in item.message
    body = render_imported_comment(item)
    for forbidden in (markdown.MARKER_OPEN, "@octocat", "<img", "](https", "\x1b", "\n<script>"):
        assert forbidden not in body
    # Tool names and rule ids only ever appear as code spans, which render no markup or mentions.
    assert "reported by `Evil\ufffd<script>@admin`**" in body
    assert "Polaris did not analyze or verify this result" in body
    envelope = review_supplied(SOURCES)
    envelope = envelope.model_copy(update={"review": report})
    assert "\x1b" not in render_workflow(envelope)


def test_tool_suppressions_result_kinds_and_message_strings():
    rule = {"id": "unused", "messageStrings": {"default": {"text": "Variable '{0}' is unused in {1}."}}}
    results = [
        fx.result("src/app.ts", 1, rule="a", suppressions=[{"kind": "inSource"}]),
        fx.result("src/app.ts", 2, rule="b", suppressions=[{"kind": "external", "status": "accepted"}]),
        fx.result("src/app.ts", 3, rule="c", suppressions=[{"kind": "external", "status": "rejected"}]),
        fx.result("src/app.ts", 1, rule="d", suppressions=[{"kind": "inSource", "status": "underReview"}]),
        fx.result("src/app.ts", 2, rule="e", kind="pass"),
        fx.result("src/app.ts", 3, rule="f", baselineState="absent"),
        {"ruleId": "g", "kind": "review", "message": {"text": "look"}, "locations": [fx.location("lib/util.ts", 1)]},
        {"ruleId": "unused", "message": {"id": "default", "arguments": ["x", "main"]},
         "locations": [fx.location("lib/util.ts", 2)]},
    ]
    report = merge({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Linter", "rules": [rule]}},
                                                  "results": results}]})
    assert sorted(item.rule_id or "" for item in report.imported) == ["c", "d", "g", "unused"]
    assert only(report).dropped == {"not_a_problem": 2, "suppressed_by_tool": 2}
    levels = {item.rule_id: (item.level, item.severity) for item in report.imported}
    assert levels["g"] == ("none", "info") and levels["c"] == ("error", "medium")
    assert next(item.message for item in report.imported if item.rule_id == "unused") == "Variable 'x' is unused in main."
    # Only Polaris reports Polaris results: a file claiming to be it is not imported.
    claimed = merge(fx.minimal(fx.result("src/app.ts"), tool="Polaris"))
    assert claimed.imported == [] and only(claimed).dropped == {"reserved_tool_name": 1}


def test_related_checks_come_from_cwe_tags_or_a_small_curated_rule_map():
    related = sarif_import.related_check
    assert related("ruff", "S603", ()) == related("bandit", "B602", ()) == "command_injection"
    assert related("ruff", "S608", ()) == related("bandit", "B608", ()) == "sql_injection"
    assert related("ruff", "S607", ()) is None, "a partial executable path is not an injection"
    assert related("ruff", "B608", ()) is None and related("eslint", "S608", ()) is None
    assert related("eslint", "no-eval", ()) == "code_injection" and related("eslint", "no-console", ()) is None
    assert related("gitleaks", "generic-api-key", ()) == "secret_exposure"
    assert related("semgrep", "rule", ("CWE-89",)) == "sql_injection"
    assert related("codeql", "js/unused-local-variable", ("CWE-563",)) is None


def test_a_tool_that_did_not_finish_leaves_its_import_unevaluated():
    finished = merge(fx.minimal(fx.result("src/app.ts"), invocations=[{"executionSuccessful": True}]))
    assert only(finished).failed_runs == 0 and not unevaluated(finished)
    for run in ({"results": None}, {"invocations": [{"executionSuccessful": False}]}):
        report = merge({"version": "2.1.0", "runs": [{**fx.minimal(fx.result("src/app.ts"))["runs"][0], **run}]})
        assert only(report).failed_runs == 1 and unevaluated(report)
    no_results = merge({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "ESLint"}}}]})
    assert (only(no_results).status, only(no_results).failed_runs) == ("imported", 1)
    assert only(merge(fx.minimal(invocations=[{"executionSuccessful": "no"}]))).error == "invalid_sarif"


# ---- CLI: exit codes, outputs, files -------------------------------------------------------------


@pytest.fixture
def clean_change(tmp_path: Path) -> tuple[Path, str, str]:
    """A change Polaris finds nothing in, so only imported results could change an exit code."""
    root = tmp_path.resolve() / "clean"
    (root / "src").mkdir(parents=True)
    fixture_git(root, "init", "-q", "-b", "main")
    (root / "src" / "app.ts").write_text("export const x = 1;\n")
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "base")
    base = fixture_git(root, "rev-parse", "HEAD")
    (root / "src" / "app.ts").write_text("export const x = 1;\nexport const y = x + 1;\n")
    fixture_git(root, "add", "-A")
    fixture_git(root, "commit", "-q", "-m", "change")
    return root, base, fixture_git(root, "rev-parse", "HEAD")


def review_cli(root: Path, base: str, head: str, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, str]:
    code = cli.main(["workflow", "review", "--root", str(root), "--diff", f"{base}...{head}",
                     "--no-external-analyzers", *extra])
    return code, capsys.readouterr().out


def test_exit_codes_change_only_when_the_caller_opts_in(clean_change, tmp_path, capsys):
    root, base, head = clean_change
    sarif = tmp_path.resolve() / "reports"
    sarif.mkdir()
    errors, warnings = sarif / "errors.sarif", sarif / "warnings.sarif"
    errors.write_bytes(fx.dump(fx.minimal(fx.result("src/app.ts", 2), tool="ESLint")))
    warnings.write_bytes(fx.dump(fx.minimal(fx.result("src/app.ts", 2, level="warning"), tool="ESLint")))
    assert review_cli(root, base, head, capsys, "--format", "json")[0] == 0
    code, out = review_cli(root, base, head, capsys, "--format", "json", "--import-sarif", str(errors))
    report = json.loads(out)["review"]
    assert code == 0 and [item["rule_id"] for item in report["imported"]] == ["rule-1"]
    assert report["imports"][0]["status"] == "imported" and report["provenance"]["imported_digests"]
    assert review_cli(root, base, head, capsys, "--import-sarif", str(errors), "--fail-on-imported", "error")[0] == 1
    assert review_cli(root, base, head, capsys, "--import-sarif", str(warnings), "--fail-on-imported", "error")[0] == 0
    assert review_cli(root, base, head, capsys, "--import-sarif", str(warnings), "--fail-on-imported", "warning")[0] == 1
    assert review_cli(root, base, head, capsys, "--import-sarif", str(warnings), "--require-complete",
                      "--fail-on-imported", "note")[0] == 1
    # A missing or unreadable file is a rejected import: the review still runs and reports it.
    missing = str(sarif / "missing.sarif")
    code, out = review_cli(root, base, head, capsys, "--format", "json", "--import-sarif", missing)
    assert code == 0 and json.loads(out)["review"]["imports"][0] == {
        "name": "missing.sarif", "digest": None, "status": "rejected", "error": "sarif_unavailable", "tools": [],
        "runs": 0, "failed_runs": 0, "results": 0, "imported": 0, "corroborating": 0, "dropped": {}}
    assert review_cli(root, base, head, capsys, "--import-sarif", missing, "--fail-on-imported", "error")[0] == 2
    link = sarif / "link.sarif"
    link.symlink_to(errors)
    code, out = review_cli(root, base, head, capsys, "--format", "json", "--import-sarif", str(link))
    assert code == 0 and json.loads(out)["review"]["imports"][0]["error"] == "sarif_unavailable"
    code, out = review_cli(root, base, head, capsys, *(["--import-sarif", str(errors)] * 17))
    assert code == 2 and json.loads(out)["code"] == "too_many_sarif_files"
    code, out = review_cli(root, base, head, capsys, "--import-sarif", str(errors))
    assert code == 0 and "Other tools (1 result) — imported SARIF, not verified by Polaris:" in out
    assert "ERROR · rule-1 · src/app.ts:2 · correctness — Something is wrong." in out
    code, out = review_cli(root, base, head, capsys, "--format", "sarif", "--import-sarif", str(errors))
    assert [run["tool"]["driver"]["name"] for run in json.loads(out)["runs"]] == ["Polaris", "ESLint"]
    code, out = review_cli(root, base, head, capsys, "--format", "codequality", "--import-sarif", str(errors))
    assert [issue["check_name"] for issue in json.loads(out)] == ["ESLint/rule-1"]


# ---- pull-request plans and publishing ------------------------------------------------------------


def plan_cli(change: tuple[Path, str, str], capsys: pytest.CaptureFixture[str], *extra: str) -> ReviewPlan:
    root, base, head = change
    code = cli.main(["pr", "plan", "--root", str(root), "--base", base, "--head", head, "--repository", "acme/app",
                     "--pr", "7", "--no-external-analyzers", *extra])
    captured = capsys.readouterr()
    assert code == 0, captured.out
    return ReviewPlan.model_validate_json(captured.out)


def test_pr_plans_list_imported_results_by_tool_and_comment_inline_only_on_opt_in(change, tmp_path, capsys):
    root = change[0]
    imports = [argument for path in write_sarif(tmp_path.resolve() / "sarif", root)
               for argument in ("--import-sarif", path)]
    plain = plan_cli(change, capsys)
    plan = plan_cli(change, capsys, *imports)
    # Polaris's own comments, gate and resolution data are unchanged; imported ones are summary-only.
    assert [item.model_dump() for item in plan.comments] == [item.model_dump() for item in plain.comments]
    assert (plan.gate, plan.checked_paths) == (plain.gate, plain.checked_paths)
    assert plan.counts.imported_in_change == 7 and plan.counts.imported_inline == 0
    assert set(plain.detected_keys) < set(plan.detected_keys)
    imported_keys = sorted(set(plan.detected_keys) - set(plain.detected_keys))
    assert len(imported_keys) == 9 and all(key.startswith("sarif-") for key in imported_keys)
    assert sorted(plan.imported_tools) == sorted(
        tool_tag(name) for name in ("ESLint", "ruff", "CodeQL", "Semgrep OSS", "gitleaks", "golangci-lint"))
    assert set(plan.imported_paths) == {"api/route.ts", "app/util.py", "api/config.ts", "cmd/main.go"}
    summary = plan.summary
    assert ("<details><summary>Reported by other tools on changed lines (6) · imported SARIF, not verified by "
            "Polaris</summary>") in summary
    assert "- `ESLint` 9.12.0 (2)" in summary and "- `golangci-lint` (1)" in summary
    assert "  - **Error** · `no-eval` · `api/route.ts:6` — eval can be harmful." in summary
    # Corroborating results appear with the Polaris finding instead of separately.
    assert "also reported by `CodeQL` `js/request-forgery`" in summary
    assert "also reported by `ruff` `S602`, `Semgrep OSS`" in summary
    assert "`js/request-forgery` · `api/route.ts:7`" not in summary
    assert markdown.MARKER_OPEN not in summary and fx.SECRET_SNIPPET not in summary
    # Opt in: security results the tool rated error (or high/critical) get their own comment.
    security = plan_cli(change, capsys, *imports, "--inline-imported", "security")
    imported = [item for item in security.comments if item.origin == "imported"]
    assert [(item.path, item.line, item.rule_id) for item in imported] == [
        ("api/route.ts", 7, "sarif:codeql/js/request-forgery"), ("api/route.ts", 6, "sarif:eslint/no-eval")]
    assert all(item.key.startswith("sarif-") and item.suggestion == "none" for item in imported)
    assert "**Error · reported by `CodeQL`**" in imported[0].body and "not analyze or verify" in imported[0].body
    assert security.counts.imported_inline == 2 and "— inline comment" in security.summary
    errors = plan_cli(change, capsys, *imports, "--inline-imported", "errors")
    assert {item.rule_id for item in errors.comments if item.origin == "imported"} == {
        "sarif:codeql/js/request-forgery", "sarif:eslint/no-eval", "sarif:golangcilint/errcheck", "sarif:ruff/E501"}
    capped = plan_cli(change, capsys, *imports, "--inline-imported", "errors", "--max-comments", "2")
    assert len(capped.comments) == 2 and capped.comments[0].origin == "polaris"
    # Imported results change the gate only when asked to.
    quiet = plan_cli(change, capsys, *imports, "--fail-severity", "critical")
    assert quiet.gate == plain_gate(change, capsys, "--fail-severity", "critical") == "incomplete"
    assert plan_cli(change, capsys, *imports, "--fail-severity", "critical", "--fail-on-imported", "error").gate == "fail"


def plain_gate(change: tuple[Path, str, str], capsys: pytest.CaptureFixture[str], *extra: str) -> str:
    return plan_cli(change, capsys, *extra).gate


def test_a_rejected_import_resolves_no_imported_comment_and_leaves_polaris_untouched(change, tmp_path, capsys):
    root = change[0]
    good = write_sarif(tmp_path.resolve() / "sarif", root, ("eslint",))
    bad = tmp_path.resolve() / "sarif" / "broken.sarif"
    bad.write_bytes(b'{"version": "2.1.0", "runs": [' + TEXT)
    plain = plan_cli(change, capsys)
    plan = plan_cli(change, capsys, "--import-sarif", good[0], "--import-sarif", str(bad))
    # Earlier imported comments stay open; Polaris's own resolution data is untouched.
    assert plan.counts.imports_rejected == 1 and plan.imported_tools == [] and plan.imported_paths == []
    assert plan.checked_paths == plain.checked_paths and plan.gate == plain.gate
    assert plan.counts.imported_in_change == 2, "the readable file is still imported"
    assert "SARIF input `broken.sarif` was rejected (`invalid_sarif`); nothing was imported from it." in plan.summary
    assert CANARY not in plan.model_dump_json()
    capsys.readouterr()
    code = cli.main(["pr", "plan", "--root", str(root), "--base", change[1], "--head", change[2], "--repository",
                     "acme/app", "--pr", "7", "--no-external-analyzers", "--import-sarif", str(bad)])
    err = capsys.readouterr().err
    assert code == 0 and "0 imported result(s) on changed lines (0 inline, 1 SARIF file(s) rejected)" in err


def test_an_opted_in_imported_gate_cannot_pass_without_its_inputs(clean_change, tmp_path, capsys):
    sarif = tmp_path.resolve() / "reports"
    sarif.mkdir()
    errors, broken = sarif / "errors.sarif", sarif / "broken.sarif"
    errors.write_bytes(fx.dump(fx.minimal(fx.result("src/app.ts", 2), tool="ESLint")))
    broken.write_bytes(b"{")
    assert plan_cli(clean_change, capsys).gate == "pass"
    assert plan_cli(clean_change, capsys, "--import-sarif", str(errors)).gate == "pass"
    assert plan_cli(clean_change, capsys, "--import-sarif", str(errors), "--fail-on-imported", "error").gate == "fail"
    assert plan_cli(clean_change, capsys, "--import-sarif", str(broken)).gate == "pass"
    assert plan_cli(clean_change, capsys, "--import-sarif", str(broken), "--fail-on-imported", "error").gate == "incomplete"


def imported_comment(key: str, line: int) -> PlannedComment:
    return PlannedComment(key=key, finding_id="e" * 20, path="api/route.ts", line=line, severity="medium",
                          result="flagged", rule_id="sarif:eslint/no-eval", title="ESLint: no-eval",
                          body="imported body", origin="imported")


def imported_plan(comments: list[PlannedComment], *, detected: list[str] | None = None,
                  checked: list[str] | None = None, tools: tuple[str, ...] = (),
                  paths: tuple[str, ...] = ()) -> ReviewPlan:
    payload = make_plan([], detected=detected if detected is not None else [item.key for item in comments],
                        checked=checked, gate="pass").model_dump()
    payload["comments"] = [item.model_dump() for item in comments]
    payload["counts"]["inline"] = len(comments)
    payload["counts"]["imported_inline"] = sum(item.origin == "imported" for item in comments)
    payload["imported_tools"], payload["imported_paths"] = list(tools), list(paths)
    return ReviewPlan.model_validate(payload)


def test_publishing_resolves_imported_comments_only_for_completely_imported_tools():
    tag = tool_tag("ESLint")
    key = f"sarif-{tag}-" + "ab" * 12
    fake = FakeGitHub()
    receipt = publish_plan(imported_plan([imported_comment(key, 3)]), fake)
    assert receipt.posted == 1 and markdown.read_finding_marker(fake.review_comments[0]["body"]) == (key, "open")
    assert publish_plan(imported_plan([imported_comment(key, 3)]), fake).already_posted == 1

    def resolved(detected: list[str], tools: tuple[str, ...], paths: tuple[str, ...]) -> bool:
        trial = FakeGitHub()
        trial.add_review_comment("api/route.ts", 3, "imported\n\n" + markdown.finding_marker(key))
        publish_plan(imported_plan([], detected=detected, tools=tools, paths=paths), trial)
        assert all(method != "DELETE" for method, _, _ in trial.requests), "publishing never deletes comments"
        return markdown.read_finding_marker(trial.review_comments[0]["body"]) == (key, "resolved")

    assert resolved([], (tag,), ("api/route.ts",))
    assert not resolved([], (), ())  # the tool's SARIF was missing, rejected or cut at a limit
    assert not resolved([], ("0" * 8,), ("api/route.ts",))  # only another tool was imported
    assert not resolved([], (tag,), ("app/other.ts",))  # this file was not covered
    assert not resolved([key], (tag,), ("api/route.ts",))  # the tool still reports it
    # Polaris resolution is unchanged and never touches imported comments.
    fake = FakeGitHub()
    polaris = fake.add_review_comment("api/route.ts", 4, "old\n\n" + markdown.finding_marker("a1" * 12))
    imported = fake.add_review_comment("api/route.ts", 3, "imported\n\n" + markdown.finding_marker(key))
    receipt = publish_plan(imported_plan([], detected=[], checked=["api/route.ts"]), fake)
    assert receipt.resolved == 1 and polaris["body"].startswith("**Resolved:** Polaris no longer detects")
    assert markdown.read_finding_marker(imported["body"]) == (key, "open")
    receipt = publish_plan(imported_plan([], detected=[], tools=(tag,), paths=("api/route.ts",)), fake)
    assert receipt.resolved == 1 and markdown.read_finding_marker(imported["body"]) == (key, "resolved")
    assert imported["body"].startswith("**Resolved:** the tool that reported this result no longer reports it")
    assert "(imported SARIF; Polaris did not verify it)" in imported["body"]


def test_plan_schema_keeps_imported_keys_namespaced():
    tag = tool_tag("ESLint")
    key = f"sarif-{tag}-" + "cd" * 12
    assert markdown.imported_tag(key) == tag and markdown.imported_tag("ab" * 12) is None
    assert markdown.read_finding_marker("x\n\n" + markdown.finding_marker(key)) == (key, "open")
    for bad in (f"sarif-{tag}-" + "c" * 23, "sarif-XYZ-" + "c" * 24, "sarif--" + "c" * 24):
        with pytest.raises(ValueError):
            markdown.finding_marker(bad)
        assert markdown.read_finding_marker(f"<!-- polaris:finding v1 key={bad} state=open -->") is None
    with pytest.raises(ValidationError):
        imported_comment("ab" * 12, 3)  # an imported comment with a Polaris key
    with pytest.raises(ValidationError):
        comment(key, 3)  # a Polaris comment with an imported key
    with pytest.raises(ValidationError):
        PlannedComment.model_validate({**imported_comment(key, 3).model_dump(), "suggestion": "verified"})
    payload = imported_plan([imported_comment(key, 3)], tools=(tag,), paths=("api/route.ts",)).model_dump()
    ReviewPlan.model_validate(payload)
    for counts in ({"imported_inline": 0}, {"inline": 2}):
        with pytest.raises(ValidationError):
            ReviewPlan.model_validate({**payload, "counts": {**payload["counts"], **counts}})
    for change in ({"imported_paths": []}, {"imported_tools": ["NOTHEX00"]}, {"imported_paths": ["../escape.ts"]},
                   {"imported_tools": [tag] * 257}):
        with pytest.raises(ValidationError):
            ReviewPlan.model_validate({**payload, **change})
    assert PlanCounts(issues_in_change=0, questions_in_change=0, lower_severity_in_change=0, existing_in_changed_files=0,
                      inline=0, not_reviewed_files=0, suggestions_verified=0,
                      suggestions_withheld=0).imports_rejected == 0


def documented_workflow() -> dict[str, Any]:
    yaml = pytest.importorskip("yaml")
    text = (Path(__file__).resolve().parents[1] / "docs" / "pr-bot.md").read_text()
    section = text.split("**Same-repository pull requests:**", 1)[1]
    return yaml.safe_load(section.split("```yaml\n", 1)[1].split("```", 1)[0])


def test_the_documented_workflow_gives_the_tools_no_write_token():
    workflow = documented_workflow()
    assert set(workflow.get("on", workflow.get(True))) == {"pull_request"} and workflow["permissions"] == {}
    jobs = workflow["jobs"]
    assert jobs["sarif"]["permissions"] == {"contents": "read"}
    assert jobs["review"]["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert "head.repo.full_name == github.repository" in jobs["review"]["if"] and "!cancelled()" in jobs["review"]["if"]
    for name, job in jobs.items():
        for step in job["steps"]:
            assert "run" not in step or "${{" not in step["run"], f"{name}: expressions reach a script"
            if "uses" in step:
                assert re.fullmatch(r"[\w.-]+/[\w./-]+@[0-9a-f]{40}", step["uses"]), step["uses"]
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False
    download = next(step for step in jobs["review"]["steps"] if "download-artifact" in step.get("uses", ""))
    assert download["with"]["path"].startswith("${{ runner.temp }}"), "SARIF never lands in the checkout"
    plan_step = next(step for step in jobs["review"]["steps"] if "pr plan" in step.get("run", ""))
    joined = re.sub(r"\\\n\s*", " ", plan_step["run"])
    sample = {"RUNNER_TEMP": "/runner/temp", "GITHUB_WORKSPACE": "/workspace", "BASE_SHA": "a" * 40,
              "HEAD_SHA": "b" * 40, "REPOSITORY": "acme/app", "PR_NUMBER": "7"}
    words = shlex.split(re.sub(r"\$\{?([A-Z_]+)\}?", lambda match: sample[match.group(1)], joined))
    plan = cli.parser().parse_args(words[4:])
    assert (plan.pr_command, plan.no_external_analyzers) == ("plan", True)
    assert [str(path) for path in plan.import_sarif] == [
        "/runner/temp/polaris-sarif/ruff.sarif", "/runner/temp/polaris-sarif/semgrep.sarif"]
    assert "GITHUB_TOKEN" not in str(plan_step.get("env")) and "secrets." not in json.dumps(workflow)


def test_imported_models_reject_unsafe_text_and_inconsistent_counts():
    report = merge(fx.minimal(fx.result("src/app.ts")))
    (item,) = report.imported
    assert imported_key(item).startswith(f"sarif-{tool_tag('Linter')}-")
    base = item.model_dump()
    for change in ({"message": "bad\x1bline"}, {"tool": "a\u202eb"}, {"rule_id": "x\ud800"}, {"path": "../x.ts"},
                   {"path": "/etc/passwd"}, {"start_line": None, "end_line": 3}, {"start_line": 5, "end_line": 4},
                   {"related_check": "made_up"}, {"verified_by_polaris": True}, {"cwe": ["CWE-0"]},
                   {"fingerprint": "xyz"}):
        with pytest.raises(ValidationError):
            ImportedFinding.model_validate({**base, **change})
    record = only(report).model_dump()
    for change in ({"status": "rejected"}, {"error": "invalid_sarif"}, {"imported": 5},
                   {"corroborating": 2}, {"name": "a\x00b"}, {"dropped": {"made_up": 1}}):
        with pytest.raises(ValidationError):
            SarifImport.model_validate({**record, **change})
