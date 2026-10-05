"""User-level setup and doctor detection of duplicate or stale Polaris servers (temporary HOME)."""

import json
import os
import subprocess
import tomllib

import pytest

from polaris.cli import main
from polaris.integrations import doctor
from polaris.onboarding import cli as theo
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.capabilities import capability_manifest, manifest_from_analyzers


@pytest.fixture
def home(tmp_path, monkeypatch):
    folder = (tmp_path / "home").resolve()
    folder.mkdir()
    for name in ("XDG_CONFIG_HOME", "APPDATA", "POLARIS_MODEL", "CLAUDE_PROJECT_DIR", "CODEX_HOME"):
        monkeypatch.delenv(name, raising=False)
    for key, value in {"HOME": str(folder), "POLARIS_HOME": str(folder / ".polaris"), "HF_HUB_OFFLINE": "1",
                       "TRANSFORMERS_OFFLINE": "1", "GIT_CONFIG_NOSYSTEM": "1",
                       "GIT_CONFIG_GLOBAL": str(folder / ".gitconfig")}.items():
        monkeypatch.setenv(key, value)
    return folder


@pytest.fixture
def project(tmp_path, home):
    root = (tmp_path / "project").resolve()
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q", "-b", "main"], check=True, capture_output=True,
                   env={**os.environ})
    return root


def working_probe(root, timeout):
    manifest = capability_manifest(runtime=AnalysisRuntime(allow_external_analyzers=False), probe=False)
    available = manifest_from_analyzers([item.model_copy(update={"availability": "available"})
                                         for item in manifest.analyzers])
    return {"handshake": True, "tools": sorted(doctor.EXPECTED_TOOLS | doctor.WORKFLOW_TOOLS),
            "rules_available": True, "root_reported": True, "root_matches": True, "languages": [],
            "checks": [], "model_loaded": False, "workflow_capabilities": available.model_dump(mode="json")}


def test_warp_global_setup_writes_one_user_level_server_without_a_root(home, capsys):
    assert main(["setup", "warp", "--global", "--engine", "rules"]) == 0
    entry = tomllib.loads((home / ".codex" / "config.toml").read_text())["mcp_servers"]["polaris"]
    assert "--root" not in entry["args"] and "cwd" not in entry
    assert entry["args"][entry["args"].index("--model-source") + 1] == "local"
    out = capsys.readouterr().out
    assert "~/.codex/config.toml" in out and "every project" in out
    assert main(["setup", "warp", "--global", "--engine", "rules"]) == 0
    assert "Already set up" in capsys.readouterr().out


def test_theo_global_setup_is_local_without_a_prompt_or_analyzer(home, monkeypatch, capsys):
    monkeypatch.setattr(theo, "analyzer", lambda: pytest.fail("the optional analyzer was looked up"))
    assert theo.main(["setup", "--global", "--host", "warp", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scope"] == "global" and report["model_source"] == "local"
    assert report["status"] == "configured" and report["changed_files"] == [str(home / ".codex" / "config.toml")]
    assert report["host_verified"] is False


def test_claude_global_setup_never_rewrites_a_large_state_file(home, capsys):
    state = home / ".claude.json"
    state.write_text(json.dumps({"history": "x" * 2_100_000}))
    before = state.read_bytes()
    assert main(["setup", "claude-code", "--global"]) == 2
    assert "claude mcp add --scope user polaris --" in capsys.readouterr().err
    assert state.read_bytes() == before


def test_doctor_accepts_user_level_servers_and_flags_stale_and_duplicate_entries(project, home):
    assert main(["setup", "warp", "--global", "--engine", "rules"]) == 0
    report = doctor.diagnose(project, probe=working_probe)
    assert report["checks"]["configuration"]["status"] == "passed"
    assert "user-level" in report["checks"]["configuration"]["message"]
    assert report["checks"]["configured_root"]["status"] == "passed"
    assert report["checks"]["server_entries"]["status"] == "passed"
    assert report["status"] == "ready_for_host_verification", report["checks"]
    # A leftover manually imported server pointing at a removed installation.
    legacy = project / ".warp" / ".mcp.json"
    legacy.parent.mkdir()
    legacy.write_text(json.dumps({"polaris-acceptance": {
        "command": str(home / "removed" / "bin" / "python"), "args": ["-I", "-m", "polaris", "mcp"]}}))
    stale = doctor.diagnose(project, probe=working_probe)
    assert stale["status"] == "failed" and stale["checks"]["server_entries"]["status"] == "failed"
    assert "no longer exists" in stale["checks"]["server_entries"]["message"]
    assert {"location": ".warp/.mcp.json", "scope": "project", "name": "polaris-acceptance",
            "problems": ["command_missing"]} in stale["server_entries"]
    assert str(home / "removed") not in json.dumps(stale)  # locations and names only, never launch values
    legacy.unlink()
    # Two working servers visible to Warp are ambiguous (the host may start either), not broken.
    assert main(["setup", "warp", "--engine", "rules", "--project", str(project)]) == 0
    both = doctor.diagnose(project, probe=working_probe)
    assert both["checks"]["server_entries"]["status"] == "manual"
    assert "Several Polaris servers" in both["checks"]["server_entries"]["message"]


def test_doctor_reports_removed_installations_referenced_by_a_bootstrap(project, home):
    bootstrap = ("import sys; sys.argv[0] = 'polaris'; sys.path.insert(0, '/nonexistent/old-release/src'); "
                 "from polaris.cli import main; sys.exit(main())")
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"polaris": {
        "command": "/usr/bin/python3", "args": ["-I", "-B", "-c", bootstrap, "mcp", "--root", str(project)]}}}))
    report = doctor.diagnose(project, probe=working_probe)
    entry = next(item for item in report["server_entries"] if item["name"] == "polaris")
    assert "package_missing" in entry["problems"]
    assert report["checks"]["server_entries"]["status"] == "failed"
    assert "removed" in report["checks"]["server_entries"]["message"]
