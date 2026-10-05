"""Offline CI contract tests; no root mounts, hosted jobs, downloads, or project execution."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from polaris.review.analyzers import identity

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "ci/agent-native"
BASE, HEAD = "a" * 40, "b" * 40  # Synthetic Git identifiers, never release pins.


@pytest.fixture
def ci():
    spec = importlib.util.spec_from_file_location("polaris_ci_template", TEMPLATES / "required_review.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def arguments(ci, output, **changes):
    args = ci.parser().parse_args([
        "--provider", "github", "--repository", "fixture/repository", "--run-id", "123:1",
        "--base-sha", BASE, "--head-sha", HEAD, "--output-dir", str(output),
    ])
    for name, value in changes.items():
        setattr(args, name, value)
    return args


def request(**changes):
    return {
        "format": "polaris.ci-request/0.1.0", "provider": "github",
        "repository": "fixture/repository", "run_id": "123:1",
        "base_sha": BASE, "head_sha": HEAD, "issued_at": 900, "expires_at": 1100,
        "authorization": "not_requested", "guard_policy_digest": None, **changes,
    }


def report():
    return {
        "format": "polaris.workflow/0.1.0", "status": "complete", "finding_count": 0,
        "snapshot": {"kind": "git_revision", "head": HEAD, "complete": True, "fresh": True},
        "review": {
            "format": "polaris.review/0.2.0", "findings": [], "coverage": {"complete": True},
            "capabilities": {"analyzers": [
                {"analyzer_id": "semgrep-ce", "availability": "available",
                 "version": identity.RUNTIME_VERSION, "distribution_version": identity.DISTRIBUTION_VERSION,
                 "identity_digest": "sha256:" + identity.CONTRACT_SHA256},
            ]},
        },
    }


def test_github_template_only_calls_external_trusted_launcher_and_pinned_upload():
    workflow = yaml.safe_load((TEMPLATES / "github-required-review.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"pull_request"}
    assert workflow["permissions"] == {}
    job = workflow["jobs"]["polaris-required-review"]
    assert job["permissions"] == {} and job["timeout-minutes"] == 10
    assert "polaris-review-isolated" in job["runs-on"]
    run, upload = job["steps"]
    assert "${{" not in run["run"]
    assert run["shell"] == "/bin/bash --noprofile --norc -e -o pipefail {0}"
    assert run["env"]["POLARIS_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert run["env"]["POLARIS_HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert run["env"]["POLARIS_RUN_ID"] == "${{ github.run_id }}:${{ github.run_attempt }}"
    assert "/usr/bin/python3 -I -S -c" in run["run"]
    assert 'launcher = Path("/opt/polaris-ci/required_review.py")' in run["run"]
    assert "/usr/bin/env -i PATH=/usr/bin:/bin" in run["run"]
    assert "--base-sha \"$POLARIS_BASE_SHA\" --head-sha \"$POLARIS_HEAD_SHA\"" in run["run"]
    assert re.fullmatch(r"actions/upload-artifact@[0-9a-f]{40}", upload["uses"])
    assert upload["if"] == "always()" and upload["with"]["if-no-files-found"] == "error"
    assert upload["with"]["retention-days"] == 7
    assert not any(step.get("continue-on-error") for step in job["steps"])


def test_gitlab_template_does_not_acquire_or_execute_candidate_content():
    job = yaml.safe_load((TEMPLATES / "gitlab-required-review.yml").read_text())["polaris-required-review"]
    assert job["allow_failure"] is False and job["timeout"] == "10m"
    assert job["inherit"] == {"default": False, "variables": False}
    assert job["variables"]["GIT_STRATEGY"] == "empty"
    assert job["variables"]["GIT_CHECKOUT"] == "false"
    assert job["variables"]["GIT_SUBMODULE_STRATEGY"] == "none"
    assert all(job[name] == [] for name in ("before_script", "after_script", "cache", "dependencies", "needs"))
    script = "\n".join(job["script"])
    assert "/usr/bin/python3 -I -S -c" in script
    assert 'launcher = Path("/opt/polaris-ci/required_review.py")' in script
    assert '--base-sha "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --head-sha "$CI_COMMIT_SHA"' in script
    assert '--run-id "${CI_PIPELINE_ID}:${CI_JOB_ID}"' in script
    assert job["artifacts"]["when"] == "always" and job["artifacts"]["access"] == "developer"
    assert job["artifacts"]["paths"] == ["polaris-required-review/"]


@pytest.mark.parametrize("name", ["github-required-review.yml", "gitlab-required-review.yml"])
def test_templates_do_not_install_fetch_or_trust_local_receipts(name):
    text = (TEMPLATES / name).read_text()
    for forbidden in ("pip install", "uv sync", "npm ", "apt-get", "git fetch", "git clone",
                      "uses: ./", "actions/checkout", "pull_request_target:", "|| true",
                      "continue-on-error:", "--exclude", "--include", "read_receipt", "--no-external"):
        assert forbidden not in text


@pytest.mark.parametrize("bad", ["0" * 40, "abc123", "origin/main", "HEAD", "--help", "A" * 40, "b" * 41])
def test_request_rejects_zero_abbreviated_symbolic_or_option_revisions(ci, tmp_path, monkeypatch, bad):
    monkeypatch.setattr(ci.time, "time", lambda: 1000)
    with pytest.raises(ci.Refused, match="invalid_exact_revision"):
        ci.validate_request(arguments(ci, tmp_path, base_sha=bad), request(base_sha=bad))


@pytest.mark.parametrize("field,value", [
    ("provider", "gitlab"), ("repository", "different/repository"), ("run_id", "123:2"),
    ("base_sha", "c" * 40), ("head_sha", "d" * 40),
])
def test_request_must_match_independently_authenticated_event(ci, tmp_path, monkeypatch, field, value):
    monkeypatch.setattr(ci.time, "time", lambda: 1000)
    with pytest.raises(ci.Refused, match="request_identity_mismatch"):
        ci.validate_request(arguments(ci, tmp_path), request(**{field: value}))


@pytest.mark.parametrize("change", [
    {"issued_at": 1001}, {"expires_at": 999}, {"expires_at": 5000}, {"issued_at": True},
])
def test_expired_future_or_overlong_request_cannot_reuse_a_prior_pass(ci, tmp_path, monkeypatch, change):
    monkeypatch.setattr(ci.time, "time", lambda: 1000)
    with pytest.raises(ci.Refused, match="expired_control_request"):
        ci.validate_request(arguments(ci, tmp_path), request(**change))


def test_authorization_is_explicitly_unrequested_or_bound_to_exact_policy(ci, tmp_path, monkeypatch):
    monkeypatch.setattr(ci.time, "time", lambda: 1000)
    args = arguments(ci, tmp_path)
    ci.validate_request(args, request())
    ci.validate_request(args, request(authorization="guard_regressions", guard_policy_digest="sha256:" + "c" * 64))
    for change in ({"authorization": None}, {"authorization": "inferred"},
                   {"authorization": "guard_regressions"}, {"guard_policy_digest": "sha256:" + "c" * 64}):
        with pytest.raises(ci.Refused, match="explicit_authorization_selection_required"):
            ci.validate_request(args, request(**change))


@pytest.mark.parametrize("guard_policy", [False, True])
def test_generated_review_command_parses_against_integrated_cli(ci, tmp_path, guard_policy):
    # The frozen analyzer-only worktree predates this shared CLI; integrated validation supplies it.
    workflow = pytest.importorskip("polaris.workflow.cli")
    command = ci.review_command(arguments(ci, tmp_path), tmp_path, guard_policy=guard_policy)
    assert command[:5] == [str(ci.PYTHON), "-I", "-B", "-m", "polaris"]
    root = argparse.ArgumentParser()
    workflow.add_workflow_parsers(root.add_subparsers(dest="command"))
    parsed = root.parse_args(command[5:])
    assert parsed.workflow_command == "review" and parsed.require_complete
    assert parsed.diff == f"{BASE}..{HEAD}" and parsed.root == ci.INPUT
    assert parsed.semgrep == ci.SEMGREP and parsed.format == "json"
    assert parsed.guard_policy == (ci.CONTROL / "guard-policy.json" if guard_policy else None)
    assert ("api_authorization" in parsed.checks) == guard_policy
    assert parsed.include is None and parsed.exclude is None


def test_environment_is_an_allowlist_not_candidate_path_or_credentials(ci, tmp_path, monkeypatch):
    for name in ("PATH", "PYTHONPATH", "PYTHONHOME", "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS",
                 "GIT_DIR", "GIT_WORK_TREE", "GITHUB_TOKEN", "CI_JOB_TOKEN", "POLARIS_API_KEY"):
        monkeypatch.setenv(name, "SYNTHETIC_CANDIDATE_CANARY")
    env = ci.environment(tmp_path)
    assert env["PATH"] == "/usr/bin:/bin" and env["HOME"] == str(tmp_path)
    assert "SYNTHETIC_CANDIDATE_CANARY" not in env.values()
    assert env["GIT_ALLOW_PROTOCOL"] == "" and env["GIT_NO_LAZY_FETCH"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0" and env["HF_HUB_OFFLINE"] == "1"


@pytest.mark.parametrize("uid,mode", [
    (1000, stat.S_IFREG | 0o644), (0, stat.S_IFDIR | 0o775),
    (0, stat.S_IFREG | 0o666), (0, stat.S_IFLNK | 0o777), (0, stat.S_IFIFO | 0o600),
])
def test_control_paths_reject_job_owner_writable_parents_links_and_special_files(ci, monkeypatch, uid, mode):
    monkeypatch.setattr(Path, "lstat", lambda self: SimpleNamespace(st_uid=uid, st_mode=mode))
    with pytest.raises(ci.Refused, match="untrusted_control_path"):
        ci.root_owned(Path("/trusted/control/record.json"))


def test_bounded_files_and_installation_digest_bind_all_copied_files(ci, tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "root_owned", lambda path: None)  # Ownership has separate negative tests.
    first = tmp_path / "a.py"
    first.write_text("synthetic fixture")
    original = ci.tree_digest(tmp_path)
    (tmp_path / "b.py").write_text("another fixture")
    assert ci.tree_digest(tmp_path) != original
    with pytest.raises(ci.Refused, match="input_limit"):
        ci.bounded_bytes(first, 2)
    link = tmp_path / "link.py"
    link.symlink_to(first)
    with pytest.raises(OSError):
        ci.bounded_bytes(link, 100)


def fake_repository(ci, tmp_path, monkeypatch, *, observed_head=HEAD, config_keys="core.bare\n"):
    root = tmp_path / "input"
    (root / ".git").mkdir(parents=True)
    (root / ".git/config").write_text("[core]\n bare = false\n")
    monkeypatch.setattr(ci, "INPUT", root)
    monkeypatch.setattr(ci, "root_owned", lambda path: None)
    monkeypatch.setattr(ci.os, "statvfs", lambda path: SimpleNamespace(f_flag=os.ST_RDONLY))
    calls = []

    def git(arguments, home):
        calls.append(arguments)
        if arguments[0] == "config":
            return config_keys.encode()
        if arguments[-1] == "HEAD":
            return observed_head.encode()
        return arguments[-1].removesuffix("^{commit}").encode()

    monkeypatch.setattr(ci, "git_value", git)
    return calls


def test_github_merge_ref_is_not_substituted_for_requested_head(ci, tmp_path, monkeypatch):
    fake_repository(ci, tmp_path, monkeypatch, observed_head="e" * 40)
    with pytest.raises(ci.Refused, match="head_checkout_mismatch"):
        ci.validate_repository(arguments(ci, tmp_path), tmp_path)


def test_preflight_checks_exact_objects_without_fetch_or_moving_ref(ci, tmp_path, monkeypatch):
    calls = fake_repository(ci, tmp_path, monkeypatch)
    ci.validate_repository(arguments(ci, tmp_path), tmp_path)
    assert ["rev-parse", "--verify", "--end-of-options", BASE + "^{commit}"] in calls
    assert ["rev-parse", "--verify", "--end-of-options", HEAD + "^{commit}"] in calls
    assert not any(command[0] in ("fetch", "checkout", "status") for command in calls)


@pytest.mark.parametrize("key", ["remote.origin.url", "include.path", "credential.helper",
                                "core.worktree", "filter.evil.clean", "extensions.partialClone"])
def test_repo_configuration_cannot_redirect_helpers_credentials_or_partial_fetch(ci, tmp_path, monkeypatch, key):
    fake_repository(ci, tmp_path, monkeypatch, config_keys=key + "\n")
    with pytest.raises(ci.Refused, match="nonminimal_git_configuration"):
        ci.validate_repository(arguments(ci, tmp_path), tmp_path)


def test_writable_input_mount_is_rejected(ci, tmp_path, monkeypatch):
    fake_repository(ci, tmp_path, monkeypatch)
    monkeypatch.setattr(ci.os, "statvfs", lambda path: SimpleNamespace(f_flag=0))
    with pytest.raises(ci.Refused, match="immutable_input_required"):
        ci.validate_repository(arguments(ci, tmp_path), tmp_path)


@pytest.mark.parametrize("path,value", [
    (("status",), "incomplete"), (("status",), "stale"), (("finding_count",), 1),
    (("snapshot", "head"), "e" * 40), (("snapshot", "fresh"), False),
    (("snapshot", "complete"), False), (("snapshot", "kind"), "worktree"),
    (("review", "coverage", "complete"), False),
    (("review", "findings"), [{"result": "needs_context"}]),
    (("review", "capabilities", "analyzers"), []),
    (("review", "capabilities", "analyzers"),
     [{"analyzer_id": "semgrep-ce", "availability": "unavailable", "version": "1.178.0"}]),
    (("review", "capabilities", "analyzers"),
     [{"analyzer_id": "semgrep-ce", "availability": "available", "version": "99.0.0"}]),
])
def test_missing_stale_incomplete_findings_and_unavailable_analyzer_cannot_pass(ci, path, value):
    valid = report()
    assert ci.report_gate(valid, HEAD)
    data = copy.deepcopy(valid)
    target = data
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    assert not ci.report_gate(data, HEAD)


def mocked_main(ci, tmp_path, monkeypatch, *, exit_code=0, outcome=None):
    output = tmp_path.resolve() / "results"
    monkeypatch.setattr(ci.time, "time", lambda: 1000)
    monkeypatch.setattr(ci.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(ci, "control_json", lambda name: request() if name == "request.json" else {})
    monkeypatch.setattr(ci, "validate_installation", lambda pins: None)
    monkeypatch.setattr(ci, "validate_repository", lambda args, home: None)

    def review(command, home):
        assert home != tmp_path and command[:5] == [str(ci.PYTHON), "-I", "-B", "-m", "polaris"]
        assert "--guard-policy" not in command
        ci.private_json(output / "review.json", report() if outcome is None else outcome)
        return exit_code

    monkeypatch.setattr(ci, "run_review", review)
    args = ["--provider", "github", "--repository", "fixture/repository", "--run-id", "123:1",
            "--base-sha", BASE, "--head-sha", HEAD, "--output-dir", str(output)]
    return args, output


@pytest.mark.parametrize("result,expected", [(0, 0), (1, 1), (2, 2), (3, 2), (-9, 2)])
def test_nonzero_exit_is_never_hidden_by_artifact_output(ci, tmp_path, monkeypatch, result, expected):
    args, output = mocked_main(ci, tmp_path, monkeypatch, exit_code=result)
    assert ci.main(args) == expected
    status = json.loads((output / "status.json").read_bytes())
    assert status["exit_code"] == expected and status["behavior"] == "not_run"
    assert stat.S_IMODE(output.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in output.iterdir())
    before = (output / "review.json").read_bytes()
    assert ci.main(args) == 2  # Existing artifacts never substitute for a fresh review.
    assert (output / "review.json").read_bytes() == before


def test_exception_after_valid_review_still_fails_closed_without_leaking_error(ci, tmp_path, monkeypatch):
    args, output = mocked_main(ci, tmp_path, monkeypatch)
    original = ci.bounded_bytes
    calls = 0

    def read(path, limit):
        nonlocal calls
        calls += 1
        if calls > 1:
            raise OSError("SYNTHETIC_PRIVATE_DIAGNOSTIC")
        return original(path, limit)

    monkeypatch.setattr(ci, "bounded_bytes", read)
    assert ci.main(args) == 2
    status = (output / "status.json").read_text()
    assert "SYNTHETIC_PRIVATE_DIAGNOSTIC" not in status
    assert json.loads(status)["exit_code"] == 2


def test_missing_control_plane_fails_before_any_reviewer_execution(ci, tmp_path, monkeypatch):
    output = tmp_path.resolve() / "missing-control"
    monkeypatch.setattr(ci.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(ci, "CONTROL", tmp_path / "absent")
    monkeypatch.setattr(ci, "run_review", lambda *args: pytest.fail("must not execute without control plane"))
    args = arguments(ci, output)
    with pytest.raises((OSError, ci.Refused)):
        ci.control_json("request.json")
    assert ci.main(["--provider", args.provider, "--repository", args.repository,
                    "--run-id", args.run_id, "--base-sha", BASE, "--head-sha", HEAD,
                    "--output-dir", str(output)]) == 2
    assert json.loads((output / "status.json").read_bytes())["status"] == "unavailable"


def test_review_subprocess_has_private_cwd_cleared_env_no_shell_and_bounded_wait(ci, tmp_path, monkeypatch):
    observed = {}

    class Process:
        pid = 100001

        def wait(self, *, timeout):
            observed.setdefault("timeouts", []).append(timeout)
            return 0

    def popen(command, **kwargs):
        observed.update(command=command, **kwargs)
        return Process()

    monkeypatch.setattr(ci.subprocess, "Popen", popen)
    monkeypatch.setattr(ci.os, "killpg", lambda pid, signal: observed.update(killed=pid))
    assert ci.run_review(["/trusted/python", "-I"], tmp_path) == 0
    assert observed["cwd"] == tmp_path and observed["env"] == ci.environment(tmp_path)
    assert observed["stdout"] == subprocess.DEVNULL and observed["stderr"] == subprocess.DEVNULL
    assert observed.get("shell", False) is False and observed["start_new_session"]
    assert observed["timeouts"] == [300, 5] and observed["killed"] == 100001


@pytest.mark.parametrize("field", ["base_sha", "head_sha"])
def test_gitlab_all_zero_event_shas_fail_even_when_control_request_matches(ci, tmp_path, monkeypatch, field):
    monkeypatch.setattr(ci.time, "time", lambda: 1000)
    changes = {"provider": "gitlab", field: "0" * 40}
    with pytest.raises(ci.Refused, match="invalid_exact_revision"):
        ci.validate_request(arguments(ci, tmp_path, **changes), request(**changes))


@pytest.mark.parametrize("change,reason", [
    ({"approved": False}, "unapproved_installation"),
    ({"semgrep_version": "99.0.0"}, "unapproved_installation"),
    ({"setuptools_version": "81.0.0"}, "unapproved_installation"),
    ({"reviewer_tree_digest": None}, "installation_digest_mismatch"),
    ({"reviewer_tree_digest": "sha256:" + "d" * 64}, "installation_digest_mismatch"),
    ({"semgrep_tree_digest": "sha256:" + "d" * 64}, "installation_digest_mismatch"),
])
def test_missing_unapproved_or_modified_installation_pins_fail(ci, monkeypatch, change, reason):
    pins = {
        "format": "polaris.ci-installation/0.1.0", "approved": True,
        "semgrep_version": ci.SEMGREP_VERSION, "setuptools_version": "83.0.0",
        "semgrep_distribution_version": ci.SEMGREP_DISTRIBUTION,
        "analyzer_contract_digest": ci.ANALYZER_CONTRACT_DIGEST,
        "reviewer_tree_digest": "sha256:" + "c" * 64,
        "semgrep_tree_digest": "sha256:" + "c" * 64,
        **change,
    }
    monkeypatch.setattr(ci, "tree_digest", lambda path: "sha256:" + "c" * 64)
    monkeypatch.setattr(ci.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(ci.platform, "machine", lambda: "arm64")
    with pytest.raises(ci.Refused, match=reason):
        ci.validate_installation(pins)


def test_ci_graph_does_not_silently_qualify_the_linux_templates(ci, monkeypatch):
    monkeypatch.setattr(ci.platform, "system", lambda: "Linux")
    with pytest.raises(ci.Refused, match="qualified_analyzer_platform_unavailable"):
        ci.validate_installation({
            "format": "polaris.ci-installation/0.1.0", "approved": True,
            "semgrep_version": ci.SEMGREP_VERSION, "setuptools_version": "83.0.0",
            "semgrep_distribution_version": ci.SEMGREP_DISTRIBUTION,
            "analyzer_contract_digest": ci.ANALYZER_CONTRACT_DIGEST,
        })
    assert ci.ANALYZER_CONTRACT_DIGEST == "sha256:" + identity.CONTRACT_SHA256


@pytest.mark.parametrize("field", ["distribution_version", "identity_digest"])
def test_runtime_version_alone_is_not_ci_analyzer_identity(ci, field):
    candidate = report()
    del candidate["review"]["capabilities"]["analyzers"][0][field]
    assert not ci.report_gate(candidate, HEAD)


def test_control_plane_policy_digest_mismatch_prevents_any_review(ci, tmp_path, monkeypatch):
    args, output = mocked_main(ci, tmp_path, monkeypatch)
    control = tmp_path / "control"
    control.mkdir()
    (control / "guard-policy.json").write_text("{}")
    monkeypatch.setattr(ci, "CONTROL", control)
    monkeypatch.setattr(ci, "root_owned", lambda path: None)
    policy_request = request(authorization="guard_regressions", guard_policy_digest="sha256:" + "c" * 64)
    monkeypatch.setattr(ci, "control_json", lambda name: policy_request if name == "request.json" else {})
    monkeypatch.setattr(ci, "run_review", lambda *args: pytest.fail("must not run with different policy"))
    assert ci.main(args) == 2
    assert json.loads((output / "status.json").read_bytes())["reason"] == "guard_policy_digest_mismatch"


def test_review_timeout_kills_process_group_and_never_passes(ci, tmp_path, monkeypatch):
    observed = []

    class Process:
        pid = 100002

        def wait(self, *, timeout):
            if timeout == 300:
                raise subprocess.TimeoutExpired("synthetic-worker", timeout)
            return -9

    monkeypatch.setattr(ci.subprocess, "Popen", lambda *args, **kwargs: Process())
    monkeypatch.setattr(ci.os, "killpg", lambda pid, signal: observed.append(pid))
    with pytest.raises(ci.Refused, match="review_timeout"):
        ci.run_review(["/trusted/python", "-I"], tmp_path)
    assert observed == [100002]


@pytest.mark.parametrize("name", ["github-required-review.yml", "gitlab-required-review.yml"])
@pytest.mark.parametrize("mode,uid,accepted", [
    (stat.S_IFREG | 0o644, 0, True),
    (stat.S_IFREG | 0o664, 0, False),
    (stat.S_IFREG | 0o644, 1000, False),
    (stat.S_IFLNK | 0o777, 0, False),
])
def test_system_bootstrap_rejects_untrusted_launcher_before_execution(
    tmp_path, monkeypatch, name, mode, uid, accepted,
):
    template = yaml.safe_load((TEMPLATES / name).read_text())
    script = (template["jobs"]["polaris-required-review"]["steps"][0]["run"]
              if name.startswith("github") else template["polaris-required-review"]["script"][0])
    words = shlex.split(script)
    code = words[words.index("-c") + 1]
    called = []
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(sys, "argv", ["-c", "--provider", "github"])
    monkeypatch.setattr(os, "execv", lambda path, args: called.append((path, args)))

    def metadata(path):
        return SimpleNamespace(st_uid=uid, st_mode=mode if path.name == "required_review.py"
                               else stat.S_IFDIR | 0o755)

    monkeypatch.setattr(Path, "lstat", metadata)
    if accepted:
        exec(compile(code, "<trusted-ci-bootstrap>", "exec"), {})
        assert called == [("/usr/bin/python3", [
            "/usr/bin/python3", "-I", "-S", "/opt/polaris-ci/required_review.py", "--provider", "github",
        ])]
    else:
        with pytest.raises(SystemExit) as exc:
            exec(compile(code, "<trusted-ci-bootstrap>", "exec"), {})
        assert exc.value.code == 2 and called == []
