"""Subprocess protocol tests use a fake analyzer; no installed Semgrep is required."""

from __future__ import annotations

import json
import stat

import pytest

from polaris.review.analyzers import AnalysisRuntime
from polaris.review.analyzers import semgrep as adapter
from polaris.review.analyzers.identity import manifest_identity
from polaris.review.analyzers.process import ProcessResult
from polaris.review.analyzers.rule_pack import SEMGREP_VERSION
from polaris.review.capabilities import capability_manifest
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import SourceFile, WorkflowReviewConfig


def clean_payload(targets):
    return {"version": SEMGREP_VERSION, "results": [], "errors": [], "paths": {"scanned": targets}}


def finding_payload(targets):
    return {
        **clean_payload(targets),
        "results": [{
            "check_id": "polaris.js.sql-text", "path": targets[0],
            "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 10},
            "extra": {"message": "FAKE_SECRET_MUST_NOT_LEAK", "lines": "FAKE_SECRET_MUST_NOT_LEAK",
                      "metavars": {"$SQL": {"abstract_content": "FAKE_SECRET_MUST_NOT_LEAK"}}},
        }],
    }


def fake_analyzer(monkeypatch, *, payload=clean_payload, probe=None, scan=None):
    calls = []
    workspaces = []
    monkeypatch.setattr(adapter, "installed_semgrep", lambda runtime: "/trusted/bin/semgrep")
    monkeypatch.setattr(adapter, "sandbox_available", lambda: True)
    monkeypatch.setattr(adapter, "qualified_platform", lambda: True)
    monkeypatch.setattr(adapter, "installed_identity", lambda executable: manifest_identity())
    # The protocol is under test here, not the OS sandbox (test_analyzer_process.py covers the
    # wrappers): the command runs as built, so no sandbox-exec or bubblewrap binary is needed.
    monkeypatch.setattr(adapter, "sandboxed_command", lambda argv, **_: list(argv))

    def run(argv, *, cwd, env, timeout, max_output_bytes):
        assert "--config" not in argv or argv[argv.index("--config") + 1] == "polaris-rules.yaml"
        assert "--metrics=off" in argv and "--disable-version-check" in argv
        assert "--no-trace" in argv
        assert env["HOME"] == str(cwd / "home") and env["SEMGREP_SEND_METRICS"] == "off"
        assert env["PYTHONNOUSERSITE"] == "1" and env["SEMGREP_ENABLE_VERSION_CHECK"] == "0"
        assert not any(key in env for key in ("POLARIS_API_KEY", "SEMGREP_APP_TOKEN", "AWS_SECRET_ACCESS_KEY", "PYTHONPATH"))
        assert stat.S_IMODE(cwd.stat().st_mode) == 0o700
        assert timeout > 0 and max_output_bytes <= 16_000_000
        calls.append(argv)
        workspaces.append(cwd)
        if "--version" in argv:
            return probe or ProcessResult("ok", 0, f"{SEMGREP_VERSION}\n".encode())
        assert "--oss-only" in argv and "--disable-nosem" in argv and "--no-git-ignore" in argv
        assert "--no-rewrite-rule-ids" in argv and "--jobs=1" in argv and "--strict" in argv
        assert "--max-memory" in argv and "--max-target-bytes" in argv and "--timeout" in argv
        targets = [path.relative_to(cwd).as_posix() for path in sorted((cwd / "source").iterdir())]
        assert all(stat.S_IMODE((cwd / path).stat().st_mode) == 0o600 for path in targets)
        pack = json.loads((cwd / "polaris-rules.yaml").read_bytes())
        assert pack["rules"] and all(rule["metadata"]["author"] == "Polaris" for rule in pack["rules"])
        assert all("registry" not in rule["id"] for rule in pack["rules"])
        if scan is not None:
            return scan
        result = payload(targets) if callable(payload) else payload
        return ProcessResult("ok", 0, json.dumps(result).encode())

    monkeypatch.setattr(adapter, "run_bounded", run)
    return calls, workspaces


def review(runtime=None, *, config=None, source=None):
    return WorkflowReviewer(
        runtime=runtime or AnalysisRuntime(semgrep_executable="/trusted/bin/semgrep"),
        config=config or WorkflowReviewConfig(checks=["sql_injection"]),
    ).review_sources([source or SourceFile("src/route.ts", "export const value = 1;\n")])


def test_controlled_command_private_files_cleanup_and_fixed_findings(monkeypatch):
    monkeypatch.setenv("SEMGREP_APP_TOKEN", "fake-runtime-canary")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "fake-runtime-canary")
    monkeypatch.setenv("PYTHONPATH", "/untrusted/project")
    calls, workspaces = fake_analyzer(monkeypatch, payload=finding_payload)
    report = review()
    assert len(calls) == 2 and report.coverage.complete
    assert report.findings[0].path == "src/route.ts" and report.findings[0].analyzer_id == "semgrep-ce"
    assert "FAKE_SECRET_MUST_NOT_LEAK" not in report.model_dump_json()
    assert all(not workspace.exists() for workspace in workspaces)
    assert "temporary copies" in " ".join(report.notices)


def test_capability_distinguishes_unprobed_missing_disabled_and_wrong_version(monkeypatch):
    calls, _ = fake_analyzer(monkeypatch)
    analyzer = adapter.SemgrepAnalyzer(AnalysisRuntime(semgrep_executable="/trusted/bin/semgrep"))
    assert analyzer.capability().availability == "not_probed" and calls == []
    assert analyzer.capability(probe=True).availability == "available" and len(calls) == 1
    monkeypatch.setattr(adapter, "installed_semgrep", lambda runtime: None)
    assert analyzer.capability().availability == "unavailable"
    runtime = AnalysisRuntime(allow_temporary_source_files=False)
    assert adapter.SemgrepAnalyzer(runtime).capability(probe=True).availability == "disabled"
    fake_analyzer(monkeypatch, probe=ProcessResult("ok", 0, b"99.0.0\n"))
    report = review()
    semgrep = next(item for item in report.capabilities.analyzers if item.analyzer_id == "semgrep-ce")
    assert semgrep.availability == "version_mismatch" and semgrep.version == "99.0.0"
    assert not report.coverage.complete and not report.findings


@pytest.mark.parametrize("probe,reason", [
    (ProcessResult("timeout"), "analyzer_probe_timeout"),
    (ProcessResult("output_limit"), "analyzer_probe_output_limit"),
    (ProcessResult("unavailable"), "analyzer_probe_unavailable"),
    (ProcessResult("ok", 1, stderr=b"private diagnostic"), "analyzer_probe_failed"),
    (ProcessResult("ok", 0, b"untrusted version output"), "invalid_version_output"),
    (ProcessResult("ok", 0, b"\xff"), "invalid_version_output"),
])
def test_version_probe_failure_never_launches_scan(monkeypatch, probe, reason):
    calls, _ = fake_analyzer(monkeypatch, probe=probe)
    report = review()
    assert len(calls) == 1 and not report.coverage.complete and report.exit_code() == 2
    assert any(entry.reason == reason for entry in report.coverage.entries)
    assert "private diagnostic" not in report.model_dump_json()


@pytest.mark.parametrize("status", ["timeout", "output_limit", "unavailable", "error"])
def test_runtime_process_failures_are_not_clean(monkeypatch, status):
    fake_analyzer(monkeypatch, scan=ProcessResult(status, stderr=b"private source"))
    report = review()
    assert not report.coverage.complete and report.exit_code() == 2 and not report.findings
    assert any(entry.reason == f"analyzer_{status}" for entry in report.coverage.entries)
    assert "private source" not in report.model_dump_json()


def test_missing_sandbox_never_falls_back_unsandboxed(monkeypatch):
    calls, _ = fake_analyzer(monkeypatch)
    monkeypatch.setattr(adapter, "sandbox_available", lambda: False)
    report = review()
    assert not calls and not report.coverage.complete
    assert any(entry.reason == "network_sandbox_unavailable" for entry in report.coverage.entries)


@pytest.mark.parametrize("change,reason", [
    (lambda data: data.update(version="different"), "invalid_analyzer_envelope"),
    (lambda data: data.update(results={}), "invalid_analyzer_envelope"),
    (lambda data: data.update(errors=None), "invalid_analyzer_envelope"),
    (lambda data: data.update(paths={}), "invalid_analyzer_envelope"),
    (lambda data: data["paths"].update(scanned=[]), "target_not_scanned"),
    (lambda data: data["paths"].update(scanned=["../../outside.ts"]), "invalid_scan_manifest"),
    (lambda data: data.update(results=[None]), "invalid_analyzer_result"),
    (lambda data: data["results"][0].update(check_id="untrusted.registry-rule"), "invalid_analyzer_result"),
    (lambda data: data["results"][0].update(path="../../outside.ts"), "invalid_analyzer_result"),
    (lambda data: data["results"][0].update(start={"line": True}), "invalid_result_location"),
    (lambda data: data["results"][0].update(end={"line": 1000}), "invalid_result_location"),
    (lambda data: data.update(skipped_rules=["polaris.js.sql-text"]), "analyzer_rules_skipped"),
])
def test_malformed_or_incomplete_analyzer_output_is_visible(monkeypatch, change, reason):
    def payload(targets):
        data = finding_payload(targets)
        change(data)
        return data

    fake_analyzer(monkeypatch, payload=payload)
    report = review()
    assert not report.coverage.complete
    assert any(entry.reason == reason for entry in report.coverage.entries)


def test_partial_parse_keeps_evidence_but_never_becomes_clean(monkeypatch):
    def payload(targets):
        return {
            **finding_payload(targets),
            "errors": [{"type": "PartialParsing", "path": targets[0], "message": "PRIVATE_PARSER_SOURCE"}],
        }

    fake_analyzer(monkeypatch, payload=payload)
    report = review()
    assert report.findings and not report.coverage.complete
    assert any(entry.status == "partial" and entry.reason == "partial_parse" for entry in report.coverage.entries)
    assert "PRIVATE_PARSER_SOURCE" not in report.model_dump_json()


def test_result_json_and_nonzero_exit_limits(monkeypatch):
    fake_analyzer(monkeypatch, scan=ProcessResult("ok", 0, b"{"))
    assert any(entry.reason == "invalid_analyzer_json" for entry in review().coverage.entries)
    fake_analyzer(monkeypatch, scan=ProcessResult("ok", 3, json.dumps(clean_payload(["source/input-000000.ts"])).encode()))
    assert not review().coverage.complete

    def many(targets):
        data = finding_payload(targets)
        data["results"] *= 2
        return data

    fake_analyzer(monkeypatch, payload=many)
    report = review(config=WorkflowReviewConfig(checks=["sql_injection"], max_findings=1))
    assert not report.coverage.complete and not report.findings
    assert any(entry.reason == "result_limit" for entry in report.coverage.entries)


def test_supported_languages_matrix_and_no_calls_still_run_broader_rules(monkeypatch):
    calls, _ = fake_analyzer(monkeypatch)
    report = review(config=WorkflowReviewConfig())
    assert len(calls) == 2 and report.coverage.complete and not report.findings
    required = [entry for entry in report.coverage.entries if entry.required]
    # Explicitly configured Semgrep rows count alongside the built-in TypeScript analyzer.
    assert report.coverage.checks_completed == len(required)
    assert {entry.analyzer_id for entry in required} == {"polaris-ts", "semgrep-ce"}
    assert sum(entry.analyzer_id == "semgrep-ce" for entry in required) == 5
    manifest = capability_manifest(runtime=AnalysisRuntime(allow_external_analyzers=False))
    implemented = {(item.language, item.check_id, item.analyzer_id) for item in manifest.matrix}
    assert ("python", "sql_injection", "polaris-python") in implemented
    assert ("typescript", "secret_exposure", "semgrep-ce") in implemented
    assert ("python", "sql_injection", "semgrep-ce") not in implemented
    assert all(item.requires_trusted_policy for item in manifest.matrix if item.check_id == "api_authorization")


def test_large_sources_and_invalid_paths_do_not_launch_analyzer(monkeypatch):
    calls, _ = fake_analyzer(monkeypatch)
    for source in (
        SourceFile("../private.ts", "x"),
        SourceFile("private.ts", "x" * 101),
        SourceFile("tool.go", "x"),
    ):
        report = review(config=WorkflowReviewConfig(max_file_bytes=100), source=source)
        assert not report.coverage.complete
    assert calls == []


def test_matching_runtime_cannot_substitute_for_downstream_distribution_identity(monkeypatch):
    calls, _ = fake_analyzer(monkeypatch)

    def upstream(_executable):
        raise ValueError("Upstream metadata is not the derivative.")

    monkeypatch.setattr(adapter, "installed_identity", upstream)
    report = review()
    assert not calls and not report.coverage.complete
    assert any(row.reason == "qualified_analyzer_identity_required" for row in report.coverage.entries)


def test_nonqualified_platform_does_not_inherit_macos_trial(monkeypatch):
    calls, _ = fake_analyzer(monkeypatch)
    monkeypatch.setattr(adapter, "qualified_platform", lambda: False)
    report = review()
    assert not calls and not report.coverage.complete
    assert any(row.reason == "qualified_analyzer_platform_unavailable" for row in report.coverage.entries)


@pytest.mark.parametrize("kind,reason", [
    (["PartialParsing", [{"path": "source/input-000000.ts", "start": {"line": 1}, "end": {"line": 1}}]],
     "partial_parse"),
    (["PartialParsing", []], "analyzer_error"),
    (["PartialParsing", {"path": "source/input-000000.ts"}], "analyzer_error"),
    (["FutureError", []], "analyzer_error"),
    (["PartialParsing", [None]], "analyzer_error"),
    ({"type": "PartialParsing"}, "analyzer_error"),
    (None, "analyzer_error"),
])
def test_structured_and_malformed_errors_keep_findings_but_not_complete_coverage(monkeypatch, kind, reason):
    def payload(targets):
        return {**finding_payload(targets), "errors": [
            {"type": kind, "path": targets[0], "message": "PRIVATE_STRUCTURED_PARSER_SOURCE"},
        ]}

    fake_analyzer(monkeypatch, payload=payload)
    report = review()
    assert report.findings and not report.coverage.complete
    assert any(row.reason == reason and row.status == "partial" for row in report.coverage.entries)
    assert "PRIVATE_STRUCTURED_PARSER_SOURCE" not in report.model_dump_json()
