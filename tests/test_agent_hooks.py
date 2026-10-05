import io
import json
import sys

import pytest
from integration_helpers import git, isolated_home_fixture, repository_fixture  # noqa: F401

from polaris.integrations import hooks
from polaris.integrations._safe import (
    IntegrationProblem,
    offline_environment,
    run_bounded,
)
from polaris.integrations.freshness import capture_snapshot, is_fresh, read_receipt, state_directory
from polaris.integrations.reporting import compact_report, render_summary
from polaris.review.engine import Reviewer


def payload(root, host="claude-code", event="stop"):
    common = {"cwd": str(root), "session_id": "fixture-session"}
    if host == "claude-code":
        return {**common, "hook_event_name": "Stop" if event == "stop" else "PostToolUse",
                "stop_hook_active": False}
    return {**common, "conversation_id": "fixture-session", "generation_id": "fixture-turn",
            "hook_event_name": "stop" if event == "stop" else "afterFileEdit", "status": "completed",
            "workspace_roots": [str(root)], "loop_count": 0}


def envelope(report=None, *, status="complete"):
    report = report or {"findings": []}
    report["coverage"] = {"complete": status == "complete", "entries": [], "omissions": []}
    return {"format": "polaris.workflow/0.1.0", "status": status, "review": report,
            "finding_count": sum(item["result"] == "flagged" for item in report["findings"]),
            "tests_status": "not_run"}


def rule_runner(root, timeout):
    # Controlled adapter fixture; the integrated workflow service is tested separately by the lead.
    report = Reviewer(engine="rules").review_paths([root / "main.py"], root=root)
    return {"summary": compact_report(envelope(report.model_dump(mode="json"))),
            "snapshot": capture_snapshot(root).to_dict()}


def test_edit_review_correction_fresh_review_and_summary(repository):
    path = repository / "main.py"
    path.write_text("import os\n\ndef execute(value):\n    os.system('probe ' + value)\n")
    dirty = hooks.run_hook(repository, host="claude-code", event="dirty",
                           payload=payload(repository, event="dirty"))
    assert dirty["summary"]["status"] == "dirty"
    status = git(repository, "status", "--porcelain")
    first = hooks.run_hook(repository, host="claude-code", event="stop",
                           payload=payload(repository), review_runner=rule_runner)
    assert first["summary"]["finding_count"] == 1 and first["followup"] is True
    assert "main.py:3" in render_summary(first["summary"])
    assert "tests_status" in first["summary"] and first["summary"]["tests_status"] == "not_run"
    assert git(repository, "status", "--porcelain") == status
    receipt = read_receipt(repository)
    assert is_fresh(receipt, capture_snapshot(repository))
    path.write_text("def execute(value):\n    return value\n")
    assert not is_fresh(receipt, capture_snapshot(repository))
    again = {**payload(repository), "stop_hook_active": True}
    final = hooks.run_hook(repository, host="claude-code", event="stop", payload=again, review_runner=rule_runner)
    assert final["summary"]["finding_count"] == 0 and final["followup"] is False
    assert is_fresh(read_receipt(repository), capture_snapshot(repository))
    assert final["summary"]["findings_resolved"] == "not_verified"


@pytest.mark.parametrize("host", ["claude-code", "cursor"])
def test_host_specific_output_and_single_reporting_continuation(repository, host):
    first = hooks.run_hook(repository, host=host, event="stop", payload=payload(repository, host),
                           review_runner=rule_runner)
    assert first["followup"] is True
    response = hooks.host_output(host, "stop", first)
    key = "reason" if host == "claude-code" else "followup_message"
    assert "Do not edit files" in response[key]
    same = hooks.run_hook(repository, host=host, event="stop", payload=payload(repository, host),
                          review_runner=rule_runner)
    assert same["followup"] is False
    subsequent = {**payload(repository, host), "stop_hook_active": True, "loop_count": 1}
    later = hooks.run_hook(repository, host=host, event="stop", payload=subsequent, review_runner=rule_runner)
    assert later["followup"] is False and later["summary"]["status"] == "complete"


def test_recursion_guard_never_claims_a_successful_review(repository, monkeypatch):
    monkeypatch.setenv("POLARIS_AGENT_HOOK_ACTIVE", "1")
    def forbidden(*args):
        pytest.fail("recursive worker must not start")
    result = hooks.run_hook(repository, host="claude-code", event="stop",
                            payload=payload(repository), review_runner=forbidden)
    assert result["summary"]["status"] == "unavailable" and result["followup"] is False
    assert not state_directory(repository).exists()


def test_busy_worktree_is_explicit_and_does_not_replace_another_receipt(repository):
    with hooks.review_lock(state_directory(repository)):
        result = hooks.run_hook(repository, host="claude-code", event="stop",
                                payload=payload(repository), review_runner=rule_runner)
    assert result["summary"]["status"] == "busy" and result["followup"] is False
    assert read_receipt(repository) is None


def test_error_invalidates_old_receipt_and_does_not_create_an_infinite_followup(repository):
    hooks.run_hook(repository, host="claude-code", event="stop",
                   payload=payload(repository), review_runner=rule_runner)
    def broken(root, timeout):
        raise IntegrationProblem("fixture-private-error-value")
    first = hooks.run_hook(repository, host="claude-code", event="stop",
                           payload=payload(repository), review_runner=broken)
    assert first["summary"]["status"] == "unavailable"
    assert "fixture-private-error-value" not in json.dumps(first)
    assert not is_fresh(read_receipt(repository), capture_snapshot(repository))
    second = hooks.run_hook(repository, host="claude-code", event="stop",
                            payload=payload(repository), review_runner=broken)
    assert not second["followup"]


def test_edit_during_review_is_stale_even_when_worker_returns_complete(repository):
    def concurrent(root, timeout):
        reviewed = rule_runner(root, timeout)
        hooks.run_hook(root, host="claude-code", event="dirty", payload=payload(root, event="dirty"))
        return reviewed
    result = hooks.run_hook(repository, host="claude-code", event="stop",
                            payload=payload(repository), review_runner=concurrent)
    assert result["summary"]["status"] == "stale"
    assert not is_fresh(read_receipt(repository), capture_snapshot(repository))


def test_optional_stale_retry_is_bounded_and_shares_one_deadline(repository):
    deadlines = []
    def retry(root, timeout):
        deadlines.append(timeout)
        result = rule_runner(root, timeout)
        result["summary"]["status"] = "stale" if len(deadlines) == 1 else "complete"
        return result
    result = hooks.run_hook(repository, host="claude-code", event="stop", retries=1,
                            payload=payload(repository), review_runner=retry)
    assert len(deadlines) == 2 and deadlines[1] < deadlines[0] <= 20
    assert result["summary"]["status"] == "complete"
    with pytest.raises(IntegrationProblem):
        hooks.run_hook(repository, host="claude-code", event="stop", retries=2,
                       payload=payload(repository), review_runner=retry)


def test_hook_payload_cannot_redirect_worktrees_or_read_transcripts(repository, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    with pytest.raises(IntegrationProblem, match="worktree"):
        hooks.run_hook(repository, host="claude-code", event="stop",
                       payload={**payload(repository), "cwd": str(outside)}, review_runner=rule_runner)
    result = hooks.run_hook(repository, host="claude-code", event="stop",
                            payload={**payload(repository), "transcript_path": "/unreadable/private/transcript"},
                            review_runner=rule_runner)
    assert result["summary"]["status"] == "complete"


def test_worker_receipt_from_a_different_worktree_is_rejected(repository):
    def wrong(root, timeout):
        result = rule_runner(root, timeout)
        result["snapshot"]["worktree_id"] = "sha256:wrong"
        return result
    result = hooks.run_hook(repository, host="claude-code", event="stop",
                            payload=payload(repository), review_runner=wrong)
    assert result["summary"]["status"] == "error"
    assert read_receipt(repository)["snapshot"]["complete"] is False


def test_symlinked_local_state_cannot_escape_the_worktree(repository, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (repository / ".git" / "polaris-agent").symlink_to(outside, target_is_directory=True)
    with pytest.raises(IntegrationProblem, match="symbolic link"):
        hooks.run_hook(repository, host="claude-code", event="stop",
                       payload=payload(repository), review_runner=rule_runner)
    assert not list(outside.iterdir())


def test_cli_malformed_and_oversized_input_is_reported_without_echo(repository, monkeypatch, capsys):
    for raw in ("fixture-private-malformed", '{"private":"' + "x" * hooks.MAX_INPUT + '"}'):
        monkeypatch.setattr("sys.stdin", io.StringIO(raw))
        assert hooks.main(["--host", "cursor", "--event", "stop", "--root", str(repository)]) == 1
        captured = capsys.readouterr()
        assert "unavailable" in captured.err and "fixture-private-malformed" not in captured.err
        assert json.loads(captured.out) == {}


def test_worker_ignores_project_python_shadowing_and_real_environment(repository, monkeypatch):
    marker = repository / "project-code-executed"
    for name in ("polaris.py", "sitecustomize.py"):
        (repository / name).write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    monkeypatch.setenv("PYTHONPATH", str(repository))
    monkeypatch.setenv("POLARIS_API_KEY", "fixture-credential-never-consumed")
    monkeypatch.setenv("POLARIS_MODEL", "/must-not-load")
    result = hooks.run_review(repository, 20)
    assert not marker.exists()
    assert "fixture-credential-never-consumed" not in json.dumps(result)
    assert result["snapshot"]["worktree_id"] == capture_snapshot(repository).worktree_id
    # This child baseline has no workflow CLI yet; integration adds it. Neither result is fake clean.
    assert result["summary"]["status"] in {"complete", "incomplete", "unavailable"}


def test_worker_detects_changes_during_workflow_call(repository, monkeypatch, capsys):
    def workflow(argv):
        (repository / "dependency.txt").write_text("changed during review")
        print(json.dumps(envelope()))
        return 0
    monkeypatch.setattr("polaris.cli.main", workflow)
    assert hooks._worker_main(["--root", str(repository)]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["summary"]["status"] == "stale"


def test_subprocess_deadline_and_output_limit_do_not_report_success(repository, isolated_home):
    env = offline_environment(isolated_home)
    assert "POLARIS_API_KEY" not in env and env["HF_HUB_OFFLINE"] == "1"
    with pytest.raises(IntegrationProblem, match="timed out"):
        run_bounded([sys.executable, "-I", "-c", "import time; time.sleep(10)"],
                    cwd=isolated_home, env=env, timeout=0.1)
    with pytest.raises(IntegrationProblem, match="output bound"):
        run_bounded([sys.executable, "-I", "-c", "print('x' * 1000000)"],
                    cwd=isolated_home, env=env, timeout=2, max_output_bytes=1000)


def test_report_keeps_locations_and_evidence_refs_but_never_raw_evidence():
    report = {"findings": [{"result": "flagged", "path": "api.ts", "start_line": 12,
              "check_id": "secret_exposure", "finding_id": "evidence-1",
              "message": "fixture-private-message", "details": ["fixture-private-source"],
              "guidance": "fixture-private-guidance"}]}
    result = compact_report(envelope(report))
    text = render_summary(result)
    assert "api.ts:12" in text and "evidence-1" in text and "1 issue found" in text
    assert "Run `polaris check` for details." in text and "review_workflow" not in text
    assert "fixture-private" not in text + json.dumps(result)
    assert result["tests_status"] == "not_run" and result["findings_resolved"] == "not_verified"


def test_legacy_missing_coverage_and_unresolved_context_are_never_clean():
    assert compact_report({"format": "polaris.review/0.1.0"})["status"] == "incomplete"
    missing = envelope()
    missing["review"].pop("coverage")
    assert compact_report(missing)["status"] == "incomplete"
    # A finding that depends on unseen context is listed to verify (and counted), never dropped.
    unknown = envelope({"findings": [{"result": "needs_context", "check_id": "command_injection"}]})
    verify = compact_report(unknown)
    assert verify["to_verify"] == 1 and verify["findings"][0]["result"] == "needs_context"
    assert "1 to verify" in render_summary(verify)
    unsupported = envelope({"findings": [{"result": "unsupported", "check_id": "command_injection"}]})
    assert compact_report(unsupported)["status"] == "incomplete"
    gap = envelope()
    gap["review"]["coverage"]["entries"] = [{"path": "tool.go", "status": "not_checked", "required": True,
                                              "reason": "unsupported_language"}]
    assert compact_report(gap)["status"] == "incomplete"
    docs = envelope()
    docs["review"]["coverage"]["entries"] = [{"path": "README.md", "status": "not_applicable", "required": False,
                                               "reason": "not_source_code"}]
    assert compact_report(docs)["status"] == "complete"
    omitted = envelope()
    omitted["review"]["coverage"]["entries"] = [{"path": "file.unknown", "status": "unsupported"}]
    assert compact_report(omitted)["status"] == "incomplete"


def test_explicit_analyzer_is_forwarded_and_launcher_changes_invalidate(repository, tmp_path, monkeypatch, capsys):
    executable = tmp_path.resolve() / "semgrep-fixture"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    before = hooks._review_snapshot(repository, executable)
    assert is_fresh(before, hooks._review_snapshot(repository, executable))
    executable.write_text("#!/bin/sh\nexit 1\n")
    assert not is_fresh(before, hooks._review_snapshot(repository, executable))

    def workflow(argv):
        assert argv[argv.index("--semgrep") + 1] == str(executable)
        print(json.dumps(envelope()))
        return 0
    monkeypatch.setattr("polaris.cli.main", workflow)
    assert hooks._worker_main(["--root", str(repository), "--semgrep", str(executable)]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["status"] == "complete"
    with pytest.raises(IntegrationProblem, match="absolute"):
        hooks.run_review(repository, 20, semgrep=executable.relative_to(executable.parent))
