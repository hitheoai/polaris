"""Automatic temporary-fixture tests; never configure an installed editor."""

from __future__ import annotations

import io
import json
import stat
from pathlib import Path

import pytest

from polaris.onboarding import cli, hosts, state
from polaris.onboarding.errors import OnboardingProblem


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    root = tmp_path / "fixture"
    root.mkdir()
    monkeypatch.setattr(state, "home", lambda: tmp_path / "private-state")
    monkeypatch.setattr(cli, "analyzer", lambda: None)
    monkeypatch.setattr("sys.stdin", io.StringIO())
    return root


@pytest.fixture
def connector(monkeypatch):
    calls = []

    def configure(target, project, *, semgrep=None, model_source="local", engine="rules",
                  name="polaris", dry_run=False, api_url=None):
        path = project / "fixture-config.json"
        before = json.loads(path.read_text()) if path.exists() else {}
        desired = {**before, "theo": {"mode": model_source, "engine": engine, "api_url": api_url}}
        changed = before != desired
        if changed and not dry_run:
            path.write_text(json.dumps(desired))
        calls.append((target, model_source, dry_run, api_url))
        return {"format": "polaris.setup/1", "target": target, "project": str(project),
                "status": "preview" if dry_run else "configured" if changed else "unchanged",
                "changed_files": [str(path)] if changed else [], "host_verified": False,
                "model_source": model_source, "next_action": "Approve Polaris in the host."}

    monkeypatch.setattr("polaris.integrations.setup.configure_project", configure, raising=False)
    monkeypatch.setattr("polaris.integrations.doctor.diagnose", lambda *a, **kw: {
        "status": "ready_for_host_verification", "checks": {}, "live_client_verified": False,
    })
    return calls


def arguments(command, sandbox, *extra):
    return [command, "--project", str(sandbox), "--host", "warp", "--json", *extra]


def test_no_mode_never_reads_ambient_keys_or_selects_a_fallback(sandbox, connector, monkeypatch, capsys):
    monkeypatch.setenv("POLARIS_API_KEY", "synthetic-never-read")
    monkeypatch.setattr("polaris.remote.load_credentials", lambda: pytest.fail("credential read"))
    assert cli.main(arguments("setup", sandbox)) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["code"] == "mode_required"
    assert connector == [] and not state.home().exists()


def test_local_setup_is_idempotent_machine_readable_and_not_host_verification(sandbox, connector, monkeypatch, capsys):
    monkeypatch.setattr(cli, "activate", lambda *a, **kw: pytest.fail("hosted activation"))
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert not captured.err and "THEO" not in captured.out
    assert report["status"] == "ready_for_host_verification" and report["host_verified"] is False
    assert report["activation"]["status"] == "not_requested"
    first = state.read_record(sandbox, "warp")
    assert first["snapshots"][0]["before_sha256"] is None
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    assert json.loads(capsys.readouterr().out)["configuration"] == "unchanged"
    assert state.read_record(sandbox, "warp")["snapshots"] == first["snapshots"]
    assert stat.S_IMODE(state.record_path(sandbox, "warp").stat().st_mode) == 0o600


def test_remote_mode_is_pinned_only_after_validated_activation(sandbox, connector, monkeypatch, capsys):
    seen = []

    def activate(url, **kwargs):
        seen.append(url)
        return {"status": "verified", "api_url": url, "auth_verified": True, "model_ready": True}

    monkeypatch.setattr(cli, "activate", activate)
    assert cli.main(arguments("setup", sandbox, "--api-url", "https://api.example/")) == 0
    value = json.loads(capsys.readouterr().out)
    assert seen == ["https://api.example"] and value["model_source"] == "remote"
    assert connector[-1] == ("warp", "remote", False, "https://api.example")
    assert value["host_verified"] is False


def test_activation_failure_does_not_configure_or_silently_use_local(sandbox, connector, monkeypatch, capsys):
    def refuse(*args, **kwargs):
        raise OnboardingProblem("model_unavailable", "No model is ready.", exit_code=1)

    monkeypatch.setattr(cli, "activate", refuse)
    assert cli.main(arguments("setup", sandbox, "--api-url", "https://api.example")) == 1
    assert json.loads(capsys.readouterr().out)["code"] == "model_unavailable"
    assert connector == [("warp", "remote", True, "https://api.example")]
    assert not (sandbox / "fixture-config.json").exists()


def test_preview_performs_no_writes_activation_or_health_probe(sandbox, connector, monkeypatch, capsys):
    monkeypatch.setattr(cli, "activate", lambda *a, **kw: pytest.fail("activation in preview"))
    monkeypatch.setattr("polaris.integrations.doctor.diagnose", lambda *a, **kw: pytest.fail("probe in preview"))
    assert cli.main(arguments("setup", sandbox, "--api-url", "https://api.example", "--dry-run")) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "preview"
    assert not state.home().exists() and list(sandbox.iterdir()) == []


def test_incomplete_health_is_not_a_finished_connection(sandbox, connector, monkeypatch, capsys):
    monkeypatch.setattr("polaris.integrations.doctor.diagnose", lambda *a, **kw: {"status": "incomplete", "checks": {}})
    assert cli.main(arguments("setup", sandbox, "--local")) == 1
    value = json.loads(capsys.readouterr().out)
    assert value["status"] == "local_health_incomplete" and value["host_verified"] is False


def test_status_is_receipt_only_and_does_not_revalidate_remote(sandbox, connector, monkeypatch, capsys):
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    capsys.readouterr()
    monkeypatch.setattr("polaris.remote.load_credentials", lambda: pytest.fail("credential read"))
    monkeypatch.setattr("polaris.integrations.doctor.diagnose", lambda *a, **kw: pytest.fail("live probe"))
    assert cli.main(arguments("status", sandbox)) == 0
    value = json.loads(capsys.readouterr().out)
    assert value["network_used"] is False and value["host_verified"] is False


def test_disconnect_restores_original_mode_and_preserves_other_configuration(sandbox, connector, capsys):
    path = sandbox / "fixture-config.json"
    original = '{"unrelated": {"private": "synthetic-test-only"}}'
    path.write_text(original)
    path.chmod(0o640)
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    capsys.readouterr()
    assert cli.main(arguments("disconnect", sandbox, "--yes")) == 0
    assert path.read_text() == original and stat.S_IMODE(path.stat().st_mode) == 0o640
    assert "synthetic-test-only" not in capsys.readouterr().out
    # A second connection uses a fresh private backup rather than replacing the previous one.
    assert cli.main(arguments("setup", sandbox, "--local")) == 0


def test_disconnect_refuses_later_edits_even_after_an_idempotent_setup(sandbox, connector, capsys):
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    path = sandbox / "fixture-config.json"
    value = json.loads(path.read_text())
    value["new_unrelated_server"] = {"enabled": True}
    path.write_text(json.dumps(value))
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    capsys.readouterr()
    before = path.read_bytes()
    assert cli.main(arguments("disconnect", sandbox, "--yes")) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "files_changed"
    assert path.read_bytes() == before


@pytest.mark.parametrize("rerun", [False, True])
def test_disconnect_refuses_later_permission_only_changes(sandbox, connector, capsys, rerun):
    assert cli.main(arguments("setup", sandbox, "--local")) == 0
    path = sandbox / "fixture-config.json"
    before = path.read_bytes()
    original_mode = stat.S_IMODE(path.stat().st_mode)
    changed_mode = 0o640 if original_mode != 0o640 else 0o600
    path.chmod(changed_mode)
    if rerun:
        assert cli.main(arguments("setup", sandbox, "--local")) == 0
    capsys.readouterr()
    assert cli.main(arguments("disconnect", sandbox, "--yes")) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "files_changed"
    assert path.read_bytes() == before and stat.S_IMODE(path.stat().st_mode) == changed_mode


def test_recovery_requires_confirmation(sandbox, capsys):
    assert cli.main(arguments("disconnect", sandbox)) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "confirmation_required"
    assert not state.home().exists()


def test_host_detection_uses_evidence_and_does_not_guess_from_the_project(sandbox):
    assert hosts.candidates({"TERM_PROGRAM": "WarpTerminal"}) == ["warp"]
    assert hosts.candidates({"TERM_PROGRAM": "vscode", "CURSOR_SESSION_ID": "fixture"}) == ["cursor"]
    assert hosts.candidates({"TERM_PROGRAM": "WarpTerminal", "CLAUDECODE": "1"}) == ["warp", "claude-code"]
    assert hosts.candidates({}) == []


def test_unrecognized_secret_arguments_are_not_echoed(capsys):
    secret = "synthetic-secret-should-not-print"
    assert cli.main(["setup", "--api-key", secret, "--json"]) == 2
    captured = capsys.readouterr()
    assert secret not in captured.out + captured.err
    assert json.loads(captured.out)["code"] == "invalid_arguments"


@pytest.mark.parametrize("value", ["/", str(Path.home())])
def test_unbounded_projects_are_rejected(value):
    with pytest.raises(OnboardingProblem):
        state.project_root(Path(value))


@pytest.mark.parametrize("boundary", ["home", "home_parent", "state", "state_parent", "state_child"])
def test_canonical_scope_cannot_bypass_an_aliased_home(tmp_path, monkeypatch, boundary):
    real_home = tmp_path / "users" / "home"
    real_state = real_home / ".polaris" / "theo"
    (real_state / "projects").mkdir(parents=True)
    alias = tmp_path / "home-alias"
    alias.symlink_to(real_home, target_is_directory=True)
    monkeypatch.setenv("HOME", str(alias))
    monkeypatch.setattr(state, "home", lambda: Path.home() / ".polaris" / "theo")
    paths = {
        "home": real_home,
        "home_parent": real_home.parent,
        "state": real_state,
        "state_parent": real_state.parent,
        "state_child": real_state / "projects",
    }
    with pytest.raises(OnboardingProblem):
        state.project_root(paths[boundary])
    project = real_home / "project"
    project.mkdir()
    assert state.project_root(project) == project


@pytest.mark.parametrize("boundary", ["state", "state_parent", "state_child"])
def test_canonical_scope_cannot_bypass_aliased_private_state(tmp_path, monkeypatch, boundary):
    real_state = tmp_path / "account-store" / "theo"
    (real_state / "projects").mkdir(parents=True)
    alias = tmp_path / "state-alias"
    alias.symlink_to(real_state, target_is_directory=True)
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    monkeypatch.setattr(state, "home", lambda: alias)
    paths = {
        "state": real_state,
        "state_parent": real_state.parent,
        "state_child": real_state / "projects",
    }
    with pytest.raises(OnboardingProblem):
        state.project_root(paths[boundary])


@pytest.mark.parametrize("ancestor", [False, True])
def test_project_scope_still_rejects_caller_symlinks(tmp_path, monkeypatch, ancestor):
    project = tmp_path / "work" / "project"
    project.mkdir(parents=True)
    alias = tmp_path / "project-alias"
    alias.symlink_to(project.parent if ancestor else project, target_is_directory=True)
    monkeypatch.setenv("HOME", str(tmp_path / "user-home"))
    with pytest.raises(OnboardingProblem) as caught:
        state.project_root(alias / "project" if ancestor else alias)
    assert caught.value.code == "unsafe_project"
    assert not list(project.iterdir())


def test_project_lock_is_exclusive_and_releases_after_interruption(sandbox):
    with state.project_lock(sandbox, "warp"):
        with pytest.raises(OnboardingProblem, match="Another Theo"):
            with state.project_lock(sandbox, "warp"):
                pass
    with state.project_lock(sandbox, "warp"):
        pass


def test_review_delegates_to_static_workflow_not_ambient_remote(sandbox, monkeypatch):
    seen = []
    monkeypatch.setattr("polaris.cli.main", lambda args: seen.extend(args) or 1)
    assert cli.main(["review", "--project", str(sandbox), "--files", "one.py", "--json"]) == 1
    assert seen[:2] == ["workflow", "review"] and "--model-source" not in seen


def test_public_entry_points_and_module_metadata_agree():
    import tomllib

    import polaris

    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text())["project"]
    assert project["version"] == polaris.__version__ == "0.4.0"
    assert project["scripts"]["polaris"] == "polaris.cli:main"
    assert project["scripts"]["theo"] == "polaris.onboarding.cli:main"
