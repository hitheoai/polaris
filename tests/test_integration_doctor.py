import json

import pytest
from integration_helpers import isolated_home_fixture, repository_fixture  # noqa: F401

from polaris.cli import main
from polaris.integrations import doctor
from polaris.integrations.setup import EDITOR_SETUP, EDITORS, configure_project
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.capabilities import capability_manifest, manifest_from_analyzers


def working_probe(root, timeout):
    manifest = capability_manifest(runtime=AnalysisRuntime(allow_external_analyzers=False), probe=False)
    # The diagnostic fake explicitly reports available analyzers; it does not run them.
    available = manifest_from_analyzers([
        item.model_copy(update={"availability": "available"}) for item in manifest.analyzers
    ])
    return {"handshake": True, "tools": sorted(doctor.EXPECTED_TOOLS | doctor.WORKFLOW_TOOLS),
            "rules_available": True, "root_reported": True, "root_matches": True,
            "languages": ["python"], "checks": ["sql_injection", "command_injection"], "model_loaded": False,
            "workflow_capabilities": available.model_dump(mode="json")}


def setup(root):
    assert main(["setup", "warp", "--project", str(root), "--engine", "rules"]) == 0


def test_doctor_exposes_actual_probe_results_but_not_live_client_approval(repository):
    setup(repository)
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["status"] == "ready_for_host_verification"
    assert report["checks"]["mcp_root"]["status"] == "passed"
    assert report["checks"]["offline_rules"]["status"] == "passed"
    assert report["checks"]["warp_completion"]["status"] == "manual"
    assert not report["live_client_verified"] and not report["credentials_used"]


def test_doctor_never_executes_arbitrary_config_commands_or_environment_values(repository):
    setup(repository)
    path = repository / ".mcp.json"
    data = json.loads(path.read_text())
    data["mcpServers"]["polaris"]["command"] = "/untrusted/polaris"
    data["mcpServers"]["polaris"]["args"] = ["mcp", "--root", str(repository), "--model-source", "local"]
    data["mcpServers"]["polaris"]["env"] = {"ARBITRARY": "fixture-private-config"}
    path.write_text(json.dumps(data))
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["checks"]["configured_command"]["status"] == "manual"
    assert "fixture-private-config" not in json.dumps(report)


def test_doctor_missing_expanded_analysis_does_not_report_ready(repository):
    setup(repository)

    def disabled(root, timeout):
        # Built-in TypeScript analysis unavailable (e.g. its tree-sitter grammar failed to load).
        manifest = capability_manifest(
            runtime=AnalysisRuntime(allow_external_analyzers=False), probe=False,
        ).model_dump(mode="json")
        for item in (*manifest["analyzers"], *manifest["matrix"]):
            if item["analyzer_id"] == "polaris-ts":
                item["availability"] = "unavailable"
        return {**working_probe(root, timeout), "workflow_capabilities": manifest}

    report = doctor.diagnose(repository, probe=disabled)
    assert report["status"] == "incomplete"
    assert report["checks"]["offline_rules"]["status"] == "passed"
    assert report["checks"]["workflow_analysis"]["status"] == "unavailable"
    assert any(row["language"] == "typescript" for row in report["workflow_capabilities"]["matrix"])


def test_doctor_requires_positive_default_matrix_coverage(repository):
    setup(repository)

    def missing_rows(root, timeout):
        result = working_probe(root, timeout)
        result["workflow_capabilities"]["matrix"] = []
        return result

    report = doctor.diagnose(repository, probe=missing_rows)
    assert report["status"] == "incomplete"
    assert report["checks"]["workflow_analysis"]["status"] == "unavailable"


def test_doctor_wrong_root_missing_rules_and_unavailable_mcp_are_not_success(repository):
    setup(repository)
    def wrong(root, timeout):
        return {**working_probe(root, timeout), "root_matches": False}
    assert doctor.diagnose(repository, probe=wrong)["status"] == "failed"
    def unavailable(root, timeout):
        raise ValueError("fixture-private-process-error")
    report = doctor.diagnose(repository, probe=unavailable)
    assert report["status"] == "failed" and "fixture-private" not in json.dumps(report)
    def legacy(root, timeout):
        return {**working_probe(root, timeout), "root_reported": False, "root_matches": False,
                "tools": ["capabilities", "review_changes", "review_code"]}
    # An older server without review_workflow can't run the current review: never ready.
    old = doctor.diagnose(repository, probe=legacy)
    assert old["status"] == "failed" and "older Polaris" in old["checks"]["mcp_tools"]["message"]


def test_doctor_ancestor_symlink_is_reported_and_never_followed(repository, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (repository / ".mcp.json").symlink_to(outside, target_is_directory=True)
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["checks"]["configuration"]["status"] == "failed"
    assert not list(outside.iterdir())


def test_real_offline_mcp_handshake_tools_and_rule_probe(repository, monkeypatch):
    pytest.importorskip("mcp")
    setup(repository)
    marker = repository / "project-code-executed"
    (repository / "polaris.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    monkeypatch.setenv("POLARIS_API_KEY", "fixture-doctor-credential")
    monkeypatch.setenv("POLARIS_MODEL", "/must-not-load")
    monkeypatch.setenv("PYTHONPATH", str(repository))
    observed = doctor.probe_mcp(repository, 20)
    assert observed["handshake"] is True
    assert set(observed["tools"]) >= doctor.EXPECTED_TOOLS
    assert observed["rules_available"] is True and observed["model_loaded"] is False
    assert not marker.exists()
    assert "fixture-doctor-credential" not in json.dumps(observed)


def test_doctor_never_infers_trust_in_analyzer_paths_from_configuration(repository, tmp_path):
    executable = tmp_path.resolve() / "semgrep-fixture"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    assert main(["setup", "warp", "--project", str(repository), "--semgrep", str(executable)]) == 0
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["checks"]["analyzer_configuration"]["status"] == "manual"
    report = doctor.diagnose(repository, probe=working_probe, semgrep=executable)
    assert report["checks"]["analyzer_configuration"]["status"] == "passed"


@pytest.mark.parametrize("target", EDITORS)
def test_doctor_separates_configuration_protocol_and_host_states(repository, target):
    missing = doctor.diagnose(repository, target=target, probe=working_probe)
    assert missing["configuration_ready"] is False and missing["local_protocol_ready"] is True
    assert missing["host_verified"] is False and missing["remote_auth_verified"] is False
    configure_project(target, repository)
    unavailable = doctor.diagnose(repository, target=target, probe=lambda root, timeout: {})
    assert unavailable["configuration_ready"] is True and unavailable["local_protocol_ready"] is False
    healthy = doctor.diagnose(repository, target=target, probe=working_probe)
    assert healthy["configuration_ready"] is True and healthy["local_protocol_ready"] is True
    assert healthy["status"] == "ready_for_host_verification"
    assert healthy["host_verified"] is False and healthy["live_client_verified"] is False
    assert healthy["next_action"] and not (repository / ".git" / "polaris-agent").exists()


@pytest.mark.parametrize("target", EDITORS)
def test_doctor_only_accepts_workspace_interpolation_for_documented_hosts(repository, target):
    configure_project(target, repository)
    path = repository / EDITOR_SETUP[target].project_config
    if target == "codex":
        import tomlkit
        data = tomlkit.parse(path.read_text())
    else:
        data = json.loads(path.read_text())
    entry = data[EDITOR_SETUP[target].servers_key]["polaris"]
    entry["args"][entry["args"].index("--root") + 1] = "${workspaceFolder}"
    path.write_text(tomlkit.dumps(data) if target == "codex" else json.dumps(data))
    report = doctor.diagnose(repository, target=target, probe=working_probe)
    expected = "passed" if target in ("cursor", "vscode") else "failed"
    assert report["checks"]["configured_root"]["status"] == expected
    assert report["configuration_ready"] is (expected == "passed")


@pytest.mark.parametrize("arguments", [
    ["--root"], ["--root="], ["--root", "fixture-private-root", "--root", "fixture-private-root"],
    ["--root", "fixture-private-root", "--root=fixture-private-other"],
    ["--model-source"], ["--model-source=local", "--model-source=remote"],
    ["--semgrep", "/fixture-private-a", "--semgrep-executable", "/fixture-private-b"],
])
def test_doctor_rejects_missing_duplicate_or_conflicting_launch_options(repository, arguments):
    setup(repository)
    path = repository / ".mcp.json"
    data = json.loads(path.read_text())
    entry = data["mcpServers"]["polaris"]
    entry["args"] = [*entry["args"][:4], "mcp", *arguments]
    path.write_text(json.dumps(data))
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["checks"]["configuration"]["status"] == "failed"
    assert report["configuration_ready"] is False
    assert "fixture-private" not in json.dumps(report)


def test_doctor_does_not_enable_a_disabled_codex_server_or_ignore_effective_override(repository):
    import tomlkit

    configure_project("codex", repository)
    path = repository / ".codex" / "config.toml"
    data = tomlkit.parse(path.read_text())
    data["mcp_servers"]["polaris"]["enabled"] = False
    path.write_text(tomlkit.dumps(data))
    (repository / "AGENTS.override.md").write_text("# Different effective guidance\n")
    before = path.read_bytes()
    report = doctor.diagnose(repository, target="codex", probe=working_probe)
    assert not report["configuration_ready"] and report["status"] == "incomplete"
    assert report["checks"]["guidance"]["status"] == "manual"
    assert report["checks"]["server_enablement"]["status"] == "manual"
    assert path.read_bytes() == before


def test_doctor_legacy_warp_manual_import_file_is_not_native_discovery_evidence(repository):
    setup(repository)
    legacy = repository / ".warp" / ".mcp.json"
    legacy.parent.mkdir()
    (repository / ".mcp.json").rename(legacy)
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["checks"]["configuration"]["status"] == "failed"
    assert "File-based MCP Servers" in report["next_action"]


def test_doctor_remote_auth_is_never_inferred_from_configuration_or_internal_probe(repository):
    configure_project("warp", repository, model_source="remote", engine="hybrid",
                      api_url="https://approved.example.test")
    report = doctor.diagnose(repository, probe=working_probe)
    assert report["configuration_ready"] and report["local_protocol_ready"]
    assert report["checks"]["hosted_origin"]["status"] == "passed"
    assert report["remote_auth_verified"] is False and report["credentials_used"] is False
    assert report["host_verified"] is False
    path = repository / ".mcp.json"
    data = json.loads(path.read_text())
    data["mcpServers"]["polaris"].pop("env")
    path.write_text(json.dumps(data))
    unpinned = doctor.diagnose(repository, probe=working_probe)
    assert unpinned["configuration_ready"] is False
    assert unpinned["checks"]["hosted_origin"]["status"] == "manual"


def test_doctor_does_not_promote_a_nested_project_or_require_git(repository, tmp_path):
    for root in (repository / "nested", tmp_path / "plain"):
        root.mkdir()
        configure_project("warp", root)
        inspected = []

        def probe(bound, timeout, inspected=inspected):
            inspected.append(bound)
            return working_probe(bound, timeout)

        report = doctor.diagnose(root, probe=probe)
        assert inspected == [root] and report["configuration_ready"]
