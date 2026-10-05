"""Repair composition boundaries; fixture source is never executed."""

from __future__ import annotations

import json
import os
import socket
import subprocess
from collections import Counter

import pytest

from polaris.cli import main
from polaris.engineering import (
    FindingReference,
    OpenAICompatibleGateway,
    capture_supplied_snapshot,
    propose_supplied_patch,
    validate_supplied_proposal,
    verify_supplied_proposal,
)
from polaris.jsonio import digest_text
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import (
    CheckCoverage,
    CoverageSummary,
    SourceFile,
    TrustedGuardPolicy,
    WorkflowReviewConfig,
)
from polaris.workflow import repair
from polaris.workflow.requests import CandidateRequest
from polaris.workflow.service import review_supplied, review_workspace

BAD = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = " + name)\n'
GOOD = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = ?", (name,))\n'
NEW_COMMAND_ISSUE = GOOD + '\nimport os\n\ndef launch(value):\n    os.system("echo " + value)\n'
RELATED = "related = True\n"
MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
SQL = WorkflowReviewConfig(checks=["sql_injection"])
BOTH = WorkflowReviewConfig(checks=["sql_injection", "command_injection"])


@pytest.fixture(autouse=True)
def isolated_boundaries(tmp_path, monkeypatch):
    home = tmp_path / "isolated-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / "cache"))
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.delenv("POLARIS_MODEL", raising=False)

    def forbidden(*args, **kwargs):
        pytest.fail("Composition tests must not execute fixture code, contact a network, or call a provider")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(OpenAICompatibleGateway, "generate", forbidden)
    popen = subprocess.Popen

    def git_only(argv, *args, **kwargs):
        if (
            not isinstance(argv, (list, tuple))
            or not argv
            or str(argv[0]) not in ("/usr/bin/git", "/bin/git")
            or kwargs.get("shell")
        ):
            forbidden()
        return popen(argv, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", git_only)


@pytest.fixture
def workspace(tmp_path):
    root = (tmp_path / "project").resolve()
    root.mkdir()
    subprocess.run(
        ["/usr/bin/git", "--no-pager", "-c", "init.templateDir=",
         "-c", f"core.hooksPath={os.devnull}", "init", "-q", str(root)],
        check=True,
        env={
            "PATH": os.defpath, "HOME": str(tmp_path),
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
        },
    )
    (root / "app.py").write_text(BAD, encoding="utf-8")
    return root


def _candidate(report, replacement=GOOD):
    flagged = [
        item for item in report.review.findings
        if item.path == "app.py" and item.check_id == "sql_injection" and item.result == "flagged"
    ]
    assert len(flagged) == 1
    return CandidateRequest.model_validate({
        "edits": [{
            "path": "app.py", "before_sha256": digest_text(BAD), "replacement": replacement,
            "finding_refs": [flagged[0].finding_id],
        }],
        "rationale": "Repair the observed SQL finding.",
        "expected_snapshot_digest": report.snapshot.digest,
    })


def _supplied_proposal(*, replacement=GOOD, config=SQL, related=None):
    sources = [SourceFile("app.py", BAD)]
    sources.extend(SourceFile(path, text) for path, text in (related or {}).items())
    report = review_supplied(sources, config=config, runtime=MEMORY)
    return repair.propose_supplied(
        sources, _candidate(report, replacement), config=config, runtime=MEMORY,
    )


def _verify_supplied(proposal, *, replacement=GOOD, config=SQL, context_sources=None):
    return verify_supplied_proposal(
        {"app.py": replacement}, proposal, expected_proposal_digest=proposal.proposal_digest,
        context=proposal.snapshot.context, context_sources=context_sources,
        static_reviewer=repair.static_adapter(config=config, runtime=MEMORY),
    )


def _local_proposal(workspace, *, replacement=GOOD, config=SQL, guard_policy=None):
    report = review_workspace(workspace, config=config, runtime=MEMORY, guard_policy=guard_policy)
    return repair.propose_local(
        workspace, _candidate(report, replacement), config=config, runtime=MEMORY,
        guard_policy=guard_policy,
    )


def _verify_args(workspace, proposal_path, proposal, *, config=SQL, policy_path=None):
    args = [
        "workflow", "verify", "--root", str(workspace), "--proposal", str(proposal_path),
        "--expected-proposal", proposal.proposal_digest, "--checks", ",".join(config.checks),
        "--no-external-analyzers",
    ]
    if policy_path is not None:
        args.extend(("--guard-policy", str(policy_path)))
    return args


def test_supplied_repair_keeps_actual_new_check_findings():
    proposal = _supplied_proposal(replacement=NEW_COMMAND_ISSUE, config=BOTH)
    result = _verify_supplied(proposal, replacement=NEW_COMMAND_ISSUE, config=BOTH)
    assert result.status == "verified_snapshot"
    assert result.static_review.status == "completed"
    assert {item.status for item in result.findings} == {"no_longer_detected"}
    additional = result.static_review.additional_findings
    assert additional and {item.check_id for item in additional} == {"command_injection"}
    assert {item.path for item in additional} == {"app.py"}
    assert {item.result for item in additional} == {"flagged"}
    assert not {item.finding_id for item in additional} & {
        item.finding_id for item in proposal.snapshot.finding_refs
    }
    assert all(set(item.model_dump()) == {"finding_id", "path", "check_id", "result"} for item in additional)
    assert "os.system" not in result.model_dump_json()
    assert result.behavioral_tests == "not_run" and not result.behavior_proven


@pytest.mark.parametrize(("replacement", "expected_exit"), [(GOOD, 0), (NEW_COMMAND_ISSUE, 2)])
def test_cli_checks_additional_findings_after_original_finding_resolves(
    workspace, tmp_path, capsys, replacement, expected_exit
):
    proposal = _local_proposal(workspace, replacement=replacement, config=BOTH)
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(proposal.model_dump_json(), encoding="utf-8")
    (workspace / "app.py").write_text(replacement, encoding="utf-8")
    assert main(_verify_args(workspace, proposal_path, proposal, config=BOTH)) == expected_exit
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "verified_snapshot"
    assert {item["status"] for item in payload["findings"]} == {"no_longer_detected"}
    assert bool(payload["static_review"]["additional_findings"]) == (expected_exit == 2)
    assert payload["behavioral_tests"] == "not_run"


@pytest.mark.parametrize(
    "case", ["not_checked", "partial", "excluded", "absent", "other_check_only", "file_limit", "result_limit"]
)
def test_incomplete_or_absent_positive_check_coverage_never_resolves(monkeypatch, case):
    proposal = _supplied_proposal()
    report = review_supplied([SourceFile("app.py", GOOD)], config=SQL, runtime=MEMORY).review
    entries = list(report.coverage.entries)
    omissions = []
    if case in ("not_checked", "partial", "excluded"):
        entries = [
            item.model_copy(update={
                "status": "partial" if case == "partial" else "not_checked",
                "reason": case, "required": case != "excluded",
            }) if item.check_id == "sql_injection" else item
            for item in entries
        ]
    elif case in ("absent", "other_check_only"):
        entries = [item for item in entries if item.check_id != "sql_injection"]
        if case == "other_check_only":
            entries.append(CheckCoverage(
                path="app.py", language="python", check_id="command_injection",
                analyzer_id="polaris-python", status="checked", reason="python_rules_completed",
                required=False,
            ))
    else:
        omissions = [case]
    required = [item for item in entries if item.required]
    completed = [item for item in required if item.status == "checked"]
    coverage = CoverageSummary(
        files_total=1,
        files_analyzed=len({item.path for item in required if item.status != "not_checked"}),
        files_not_fully_checked=len({item.path for item in required if item.status != "checked"}),
        checks_total=len(required), checks_completed=len(completed),
        complete=len(required) == len(completed) and not omissions,
        statuses=dict(Counter(item.status for item in required)), entries=entries, omissions=omissions,
    )
    observed_report = report.model_copy(update={"coverage": coverage})
    monkeypatch.setattr(repair.WorkflowReviewer, "review_sources", lambda self, sources: observed_report)
    result = _verify_supplied(proposal)
    assert result.status == "verified_snapshot"
    assert result.static_review.status == "partial"
    assert result.static_review.analyzed_paths == ()
    assert result.static_review.unreviewed_paths == ("app.py",)
    assert {item.status for item in result.findings} == {"not_reviewed"}


def test_actual_unit_limit_does_not_resolve_original_findings():
    config = WorkflowReviewConfig(checks=["sql_injection"], max_units=1)
    replacement = GOOD + "\ndef additional_function():\n    return 1\n"
    proposal = _supplied_proposal(replacement=replacement, config=config)
    result = _verify_supplied(proposal, replacement=replacement, config=config)
    assert result.static_review.status == "partial"
    assert result.static_review.unreviewed_paths == ("app.py",)
    assert {item.status for item in result.findings} == {"not_reviewed"}


@pytest.mark.parametrize("evidence", [("unmapped-evidence",), ("check:not_a_supported_check",)])
def test_unmapped_original_check_evidence_is_not_resolved(evidence):
    original = _supplied_proposal()
    ref = original.snapshot.finding_refs[0]
    snapshot = capture_supplied_snapshot(
        {"app.py": BAD}, context=original.snapshot.context,
        finding_refs=(FindingReference(finding_id=ref.finding_id, path=ref.path, evidence_refs=evidence),),
    )
    proposal = propose_supplied_patch(
        {"app.py": BAD}, snapshot, original.edits, context=snapshot.context,
        rationale="Exercise missing check evidence without granting it authority.",
    )
    result = _verify_supplied(proposal)
    assert result.static_review.status == "partial"
    assert {item.status for item in result.findings} == {"not_reviewed"}


@pytest.mark.parametrize("change", ["unchanged", "content", "missing", "extra"])
def test_supplied_context_sources_are_bound_and_drift_blocks_review(change, monkeypatch):
    original_context = {"related.py": RELATED}
    proposal = _supplied_proposal(related=original_context)
    assert proposal.snapshot.source_kind == "submitted_content"
    assert proposal.snapshot.root_digest is None
    assert [(item.path, item.sha256) for item in proposal.snapshot.context_files] == [
        ("related.py", digest_text(RELATED)),
    ]
    assert validate_supplied_proposal(
        {"app.py": BAD}, proposal, expected_proposal_digest=proposal.proposal_digest,
        context=proposal.snapshot.context, context_sources=original_context,
    ).status == "valid"
    contexts = {
        "unchanged": original_context,
        "content": {"related.py": "related = False\n"},
        "missing": {},
        "extra": {**original_context, "extra.py": "extra = True\n"},
    }[change]
    calls = []
    observe = repair.static_adapter(config=SQL, runtime=MEMORY)

    def static_review(sources, snapshot):
        calls.append(tuple(sources))
        return observe(sources, snapshot)

    def no_workspace(*args, **kwargs):
        pytest.fail("Submitted context must not resolve server filesystem paths")

    monkeypatch.setattr("polaris.engineering.service.Workspace", no_workspace)
    result = verify_supplied_proposal(
        {"app.py": GOOD}, proposal, expected_proposal_digest=proposal.proposal_digest,
        context=proposal.snapshot.context, context_sources=contexts, static_reviewer=static_review,
    )
    if change == "unchanged":
        assert result.status == "verified_snapshot"
        assert {item.status for item in result.findings} == {"no_longer_detected"}
        assert calls == [("app.py",)]
    else:
        assert result.status == "stale" and result.error_code == "stale_context"
        assert {item.status for item in result.findings} == {"not_reviewed"}
        assert calls == []


@pytest.mark.parametrize("change", ["worktree_context", "policy_file", "policy_file_missing"])
def test_cli_rechecks_context_and_policy_after_static_review(
    workspace, tmp_path, monkeypatch, capsys, change
):
    related = workspace / "unrelated.py"
    related.write_text(RELATED, encoding="utf-8")
    policy_path = None
    guard_policy = None
    if change != "worktree_context":
        guard_policy = TrustedGuardPolicy.model_validate({
            "policy_id": "fixture", "revision": "initial",
            "requirements": [{"path": "protected.py", "symbol": "handler", "guard": "authorize"}],
        })
        policy_path = tmp_path / "trusted-policy.json"
        policy_path.write_text(guard_policy.model_dump_json(), encoding="utf-8")
        assert not policy_path.is_relative_to(workspace)
    proposal = _local_proposal(workspace, guard_policy=guard_policy)
    # Other files of the reviewed change are bound with the approval, so editing them
    # after approval (even during verification) invalidates it.
    assert "unrelated.py" in {item.path for item in proposal.snapshot.context_files}
    proposal_path = tmp_path / "proposal.json"
    proposal_path.write_text(proposal.model_dump_json(), encoding="utf-8")
    (workspace / "app.py").write_text(GOOD, encoding="utf-8")
    original = repair.WorkflowReviewer.review_sources
    calls = []

    def mutate_after_static_review(self, sources):
        observed = original(self, sources)
        calls.append(observed)
        if change == "worktree_context":
            related.write_text("related = False\n", encoding="utf-8")
        elif change == "policy_file_missing":
            policy_path.unlink()
        else:
            revised = guard_policy.model_copy(update={"revision": "changed"})
            policy_path.write_text(revised.model_dump_json(), encoding="utf-8")
        return observed

    monkeypatch.setattr(repair.WorkflowReviewer, "review_sources", mutate_after_static_review)
    exit_code = main(_verify_args(workspace, proposal_path, proposal, policy_path=policy_path))
    payload = json.loads(capsys.readouterr().out)
    assert len(calls) == 1 and calls[0].coverage.complete
    assert not calls[0].findings
    assert exit_code == 2, payload
    assert payload["format"] == "polaris.workflow-error/0.1.0"
    assert payload["code"] == ("workflow_unavailable" if change == "policy_file_missing" else "stale_context")
    assert (workspace / "app.py").read_text(encoding="utf-8") == GOOD
