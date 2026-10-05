"""Composition tests: source is fixture data, never project code to execute."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import time
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from polaris.cli import main
from polaris.engineering import (
    EngineeringError,
    ProposalApproval,
    apply_proposal,
    verify_proposal,
    verify_supplied_proposal,
)
from polaris.jsonio import digest_text
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import SourceFile, WorkflowReviewConfig
from polaris.workflow.host import host_settings
from polaris.workflow.output import to_codequality, to_sarif
from polaris.workflow.repair import active_context, propose_local, propose_supplied, static_adapter
from polaris.workflow.requests import CandidateRequest, WorkflowReviewRequest
from polaris.workflow.service import ReportStore, brief_report, review_supplied, review_workspace

BAD = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = " + name)\n'
GOOD = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = ?", (name,))\n'
MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
SQL = WorkflowReviewConfig(checks=["sql_injection"])


@pytest.fixture
def workspace(tmp_path):
    root = (tmp_path / "project").resolve()
    root.mkdir()
    subprocess.run(
        ["/usr/bin/git", "--no-pager", "init", "-q", str(root)], check=True,
        env={"PATH": os.defpath, "HOME": str(tmp_path), "GIT_CONFIG_NOSYSTEM": "1",
             "GIT_CONFIG_GLOBAL": os.devnull},
    )
    (root / "app.py").write_text(BAD)
    return root


def candidate(report, *, replacement=GOOD, path="app.py", finding=None):
    return CandidateRequest.model_validate({
        "edits": [{
            "path": path, "before_sha256": digest_text(BAD), "replacement": replacement,
            "finding_refs": [finding or report.review.findings[0].finding_id],
        }],
        "rationale": "Use a bound parameter without changing the task's scope.",
        "expected_snapshot_digest": report.snapshot.digest,
    })


def approval(proposal):
    now = int(time.time())
    return ProposalApproval(
        proposal_digest=proposal.proposal_digest, snapshot_digest=proposal.snapshot.snapshot_digest,
        approved=True, approved_at_unix=now, expires_at_unix=now + 60,
    )


def test_memory_review_preserves_explicit_scope_and_legacy_discriminator():
    report = review_supplied([SourceFile("app.py", BAD)], config=SQL)
    assert report.format == "polaris.workflow/0.1.0"
    assert report.review.format == "polaris.review/0.2.0"
    assert report.status == "complete" and report.finding_count == 1
    assert report.snapshot.kind == "submitted_content" and report.snapshot.fresh is None
    assert report.tests_status == "not_run" and report.exit_code(require_complete=True) == 1
    assert report.context.files == []


def test_unsupported_and_unavailable_are_not_clean_reviews():
    for source in (SourceFile("main.go", "package main\n"), SourceFile("App.java", "class App {}\n")):
        report = review_supplied([source])
        assert report.status == "incomplete" and not report.review.coverage.complete
        assert report.exit_code(require_complete=True) == 2
        assert brief_report(report).coverage["unreviewed_reasons"]
        sarif = to_sarif(report)
        assert not sarif["runs"][0]["invocations"][0]["executionSuccessful"]
        assert to_codequality(report)


def test_source_iterator_and_detail_pages_are_bounded():
    consumed = []

    def inputs():
        for index in range(100):
            consumed.append(index)
            yield SourceFile(f"file{index}.py", BAD)

    report = review_supplied(inputs(), config=WorkflowReviewConfig(checks=["sql_injection"], max_files=2))
    assert consumed == [0, 1, 2] and report.status == "incomplete"
    assert not report.snapshot.complete
    store = ReportStore(capacity=1)
    store.put(report)
    page = store.details(report.report_id, limit=1)
    assert len(page.findings) == 1 and len(page.coverage["entries"]) == 1
    next_report = review_supplied([SourceFile("different.py", GOOD)], config=SQL)
    store.put(next_report)
    with pytest.raises(ValueError, match="evicted"):
        store.details(report.report_id)


def test_read_only_workspace_review_and_dependency_changes(workspace):
    (workspace / "package.json").write_text('{"name":"fixture"}\n')
    first = review_workspace(workspace, config=SQL, runtime=MEMORY)
    assert first.snapshot.fresh is True and first.snapshot.complete
    assert (workspace / "app.py").read_text() == BAD
    repeated = review_workspace(workspace, config=SQL, runtime=MEMORY)
    assert repeated.snapshot.digest == first.snapshot.digest
    (workspace / "package.json").write_text('{"name":"changed"}\n')
    changed = review_workspace(workspace, config=SQL, runtime=MEMORY)
    assert changed.snapshot.digest != first.snapshot.digest


def test_mutation_during_review_is_stale(workspace, monkeypatch):
    from polaris.workflow import service

    original = service.WorkflowReviewer.review_sources

    def mutated(self, sources):
        result = original(self, sources)
        (workspace / "app.py").write_text(GOOD)
        return result

    monkeypatch.setattr(service.WorkflowReviewer, "review_sources", mutated)
    report = review_workspace(workspace, config=SQL, runtime=MEMORY)
    assert report.status == "stale" and report.snapshot.fresh is False
    assert report.exit_code(require_complete=True) == 2


def test_scope_limits_reach_git_collection(workspace):
    (workspace / "other.py").write_text(BAD)
    report = review_workspace(
        workspace, runtime=MEMORY, config=WorkflowReviewConfig(checks=["sql_injection"], max_files=1),
    )
    assert report.status == "incomplete"


def test_local_proposal_apply_verify_and_fresh_rereview(workspace):
    report = review_workspace(workspace, config=SQL, runtime=MEMORY)
    proposal = propose_local(workspace, candidate(report), config=SQL, runtime=MEMORY)
    assert proposal.origin == "host_candidate" and (workspace / "app.py").read_text() == BAD
    context = active_context(workspace, proposal, config=SQL, runtime=MEMORY)
    assert context == proposal.snapshot.context
    receipt = apply_proposal(workspace, proposal, approval=approval(proposal), context=context)
    assert receipt.status == "applied" and receipt.behavioral_tests == "not_run"
    restored = active_context(workspace, proposal, config=SQL, runtime=MEMORY, post_edit=True)
    assert restored == context
    verified = verify_proposal(
        workspace, proposal, expected_proposal_digest=proposal.proposal_digest, context=restored,
        static_reviewer=static_adapter(config=SQL, runtime=MEMORY),
    )
    assert verified.status == "verified_snapshot"
    assert verified.static_review.status == "completed"
    assert {item.status for item in verified.findings} == {"no_longer_detected"}
    assert not verified.behavior_proven and verified.behavioral_tests == "not_run"
    final = review_workspace(workspace, config=SQL, runtime=MEMORY)
    assert final.status == "complete" and final.finding_count == 0
    assert final.snapshot.digest != report.snapshot.digest


def test_changed_nonpatch_context_invalidates_approval(workspace):
    report = review_workspace(workspace, config=SQL, runtime=MEMORY)
    proposal = propose_local(workspace, candidate(report), config=SQL, runtime=MEMORY)
    (workspace / "package.json").write_text('{"new_dependency":true}\n')
    context = active_context(workspace, proposal, config=SQL, runtime=MEMORY)
    receipt = apply_proposal(workspace, proposal, approval=approval(proposal), context=context)
    assert receipt.status == "not_applied" and receipt.error_code == "stale_context"
    assert (workspace / "app.py").read_text() == BAD


def test_runtime_changes_invalidate_approval(workspace):
    report = review_workspace(workspace, config=SQL, runtime=MEMORY)
    proposal = propose_local(workspace, candidate(report), config=SQL, runtime=MEMORY)
    changed = active_context(workspace, proposal, config=SQL, runtime=replace(MEMORY, timeout_seconds=29))
    assert changed != proposal.snapshot.context
    receipt = apply_proposal(workspace, proposal, approval=approval(proposal), context=changed)
    assert receipt.status == "not_applied" and receipt.error_code == "stale_context"


def test_unobserved_finding_and_cross_file_repair_are_rejected(workspace):
    report = review_workspace(workspace, config=SQL, runtime=MEMORY)
    with pytest.raises(EngineeringError):
        propose_local(workspace, candidate(report, finding="invented"), config=SQL, runtime=MEMORY)
    (workspace / "unrelated.py").write_text(BAD)
    with pytest.raises(EngineeringError):
        propose_local(workspace, candidate(report, path="unrelated.py"), config=SQL, runtime=MEMORY)


def test_memory_only_proposals_reverify_but_cannot_be_applied_locally(workspace):
    original = [SourceFile("app.py", BAD)]
    report = review_supplied(original, config=SQL)
    proposal = propose_supplied(original, candidate(report), config=SQL)
    assert proposal.snapshot.source_kind == "submitted_content" and proposal.snapshot.root_digest is None
    result = verify_supplied_proposal(
        {"app.py": GOOD}, proposal, expected_proposal_digest=proposal.proposal_digest,
        context=proposal.snapshot.context, static_reviewer=static_adapter(config=SQL, runtime=MEMORY),
    )
    assert result.findings[0].status == "no_longer_detected"
    receipt = apply_proposal(workspace, proposal, approval=approval(proposal), context=proposal.snapshot.context)
    assert receipt.status == "not_applied" and receipt.error_code == "worktree_required"
    with pytest.raises(EngineeringError):
        propose_supplied(original * 2, candidate(report), config=SQL)


@pytest.mark.parametrize("field", ["guard_policy", "action_policy", "semgrep_executable", "runtime", "provider_url"])
def test_requests_cannot_establish_server_policy_or_execution(field):
    with pytest.raises(ValidationError):
        WorkflowReviewRequest.model_validate({"files": [{"path": "app.py", "content": GOOD}], field: "untrusted"})


@pytest.mark.parametrize("path", ["../outside.py", "/absolute.py", "C:\\outside.py", "a/../b.py"])
def test_supplied_file_labels_are_not_server_paths(path):
    with pytest.raises(ValidationError):
        WorkflowReviewRequest.model_validate({"files": [{"path": path, "content": GOOD}]})


def test_cli_incomplete_gate_private_output_and_no_overwrite(workspace, tmp_path, capsys):
    (workspace / "route.ts").write_text("export const value = 1;\n")
    output = tmp_path / "report.json"
    args = [
        "workflow", "review", "--root", str(workspace), "--no-external-analyzers",
        "--checks", "api_authorization", "--require-complete", "--format", "json", "--output", str(output),
    ]
    assert main(args) == 2
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    raw = output.read_bytes()
    assert json.loads(raw)["status"] == "incomplete"
    assert main(args) == 2 and output.read_bytes() == raw
    assert "output_unwritable" in capsys.readouterr().out


def test_cli_output_refuses_user_symlinks_but_follows_root_owned_system_links(workspace, tmp_path, capsys):
    (workspace / "route.ts").write_text("export const value = 1;\n")
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    base = ["workflow", "review", "--root", str(workspace), "--no-external-analyzers", "--format", "json"]
    assert main([*base, "--output", str(tmp_path / "link" / "report.json")]) == 2
    assert "output_unwritable" in capsys.readouterr().out
    assert not (tmp_path / "real" / "report.json").exists()
    system = Path("/tmp")
    if not (system.is_symlink() and system.lstat().st_uid == 0):
        pytest.skip("/tmp is not a root-owned symbolic link on this system")
    target = system / f"polaris-output-{os.getpid()}.json"
    try:
        main([*base, "--output", str(target)])
        assert json.loads(target.read_bytes())["format"]
    finally:
        target.unlink(missing_ok=True)


def test_cli_propose_approved_apply_and_static_verify(workspace, tmp_path, capsys):
    report = review_workspace(workspace, config=SQL, runtime=MEMORY)
    input_path = tmp_path / "candidate.json"
    input_path.write_text(candidate(report).model_dump_json())
    proposal_path = tmp_path / "proposal.json"
    options = ["--root", str(workspace), "--checks", "sql_injection", "--no-external-analyzers"]
    assert main([
        "workflow", "propose", "--input", str(input_path), "--output", str(proposal_path), *options,
    ]) == 0
    proposal = json.loads(proposal_path.read_bytes())
    digest = proposal["proposal_digest"]
    assert (workspace / "app.py").read_text() == BAD
    assert main([
        "workflow", "apply", "--proposal", str(proposal_path),
        "--approve-proposal", digest_text("not approved"), *options,
    ]) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "proposal_mismatch"
    assert (workspace / "app.py").read_text() == BAD
    assert main([
        "workflow", "apply", "--proposal", str(proposal_path), "--approve-proposal", digest, *options,
    ]) == 0
    applied = json.loads(capsys.readouterr().out)
    assert applied["status"] == "applied" and applied["behavioral_tests"] == "not_run"
    assert main([
        "workflow", "verify", "--proposal", str(proposal_path), "--expected-proposal", digest, *options,
    ]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["static_review"]["status"] == "completed"
    assert not verified["static_review"]["additional_findings"]
    assert verified["findings"][0]["status"] == "no_longer_detected"
    assert verified["behavioral_tests"] == "not_run" and verified["behavior_proven"] is False


def test_host_configuration_is_explicit_and_redacts_invalid_policy(tmp_path):
    runtime, guard, action = host_settings()
    assert not runtime.allow_external_analyzers and not runtime.allow_temporary_source_files
    assert guard is None and action is None
    bad = tmp_path / "policy.json"
    bad.write_text('{"secret-do-not-echo":')
    with pytest.raises(ValueError, match="invalid trusted host configuration") as error:
        host_settings(guard_path=bad)
    assert "secret-do-not-echo" not in str(error.value)


def test_http_workflow_routes_are_memory_only_authenticated_and_nonexecuting():
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from polaris.api.app import create_app
    from polaris.api.security import KeyStore, new_key
    from polaris.integrations import ReviewService

    raw, key = new_key("workflow-fixture")
    client = TestClient(create_app(ReviewService(), keys=KeyStore([key])), base_url="http://127.0.0.1:8780")
    payload = {"files": [{"path": "app.py", "content": BAD}], "config": {"checks": ["sql_injection"]}}
    assert client.post("/v1/workflow/review", json=payload).status_code == 401
    client.headers["Authorization"] = f"Bearer {raw}"
    response = client.post("/v1/workflow/review", json=payload)
    assert response.status_code == 200
    report = response.json()
    assert report["finding_count"] == 1 and report["snapshot"]["fresh"] is None
    unavailable = client.post("/v1/workflow/review", json={
        "files": [{"path": "main.go", "content": "package main"}],
    })
    assert unavailable.status_code == 200 and unavailable.json()["status"] == "incomplete"
    typescript = client.post("/v1/workflow/review", json={
        "files": [{"path": "route.ts", "content": "export const x = 1;"}],
    })
    assert typescript.status_code == 200 and typescript.json()["status"] == "complete"
    candidate_input = {
        "edits": [{
            "path": "app.py", "before_sha256": digest_text(BAD), "replacement": GOOD,
            "finding_refs": [report["review"]["findings"][0]["finding_id"]],
        }],
        "rationale": "Parameterize the SQL value.",
    }
    proposed = client.post("/v1/workflow/propose", json={**payload, "candidate": candidate_input})
    assert proposed.status_code == 200
    assert proposed.json()["snapshot"]["source_kind"] == "submitted_content"
    action = client.post("/v1/workflow/action", json={
        "action": {"kind": "network", "action_id": "fixture", "method": "POST", "url": "https://example.invalid/upload"},
    })
    assert action.status_code == 200
    assert action.json()["status"] == "needs_review" and action.json()["executed"] is False
    assert action.json()["authorized"] is False
    forged = client.post("/v1/workflow/action", json={
        "action": {"kind": "filesystem", "action_id": "fixture", "operation": "write", "path": "../outside"},
        "policy": {"authority": "user"},
    })
    assert forged.status_code == 422
    assert client.post("/v1/workflow/apply", json={}).status_code == 404
    assert client.post("/v1/workflow/execute", json={}).status_code == 404
