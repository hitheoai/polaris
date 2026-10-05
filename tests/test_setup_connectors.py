"""Project-only connector tests; no native application or real account is configured."""

import json
import tomllib
from pathlib import Path

import pytest
from integration_helpers import isolated_home_fixture, repository_fixture  # noqa: F401

from polaris.cli import main
from polaris.integrations import setup
from polaris.integrations._safe import IntegrationProblem, offline_environment


def entry_for(root, target):
    editor = setup.EDITOR_SETUP[target]
    path = root / editor.project_config
    data = tomllib.loads(path.read_text()) if target == "codex" else json.loads(path.read_text())
    return data[editor.servers_key]["polaris"]


@pytest.mark.parametrize("target", setup.EDITORS)
def test_structured_setup_is_silent_bounded_and_idempotent(repository, isolated_home, target, capsys):
    home_before = sorted(path.relative_to(isolated_home) for path in isolated_home.rglob("*"))
    preview = setup.configure_project(target, repository, dry_run=True)
    assert preview["format"] == "polaris.setup/1" and preview["status"] == "preview"
    assert preview["project"] == str(repository) and preview["target"] == target
    assert not preview["host_verified"] and preview["model_source"] == "local"
    # The MCP entry and the managed rule; Claude Code also gets the polaris-check skill.
    assert preview["next_action"] and len(preview["changed_files"]) == (3 if target == "claude-code" else 2)
    assert all(Path(path).is_absolute() and Path(path).is_relative_to(repository)
               and not Path(path).exists() for path in preview["changed_files"])
    assert sorted(path.relative_to(isolated_home) for path in isolated_home.rglob("*")) == home_before
    result = setup.configure_project(target, repository)
    assert result["changed_files"] == preview["changed_files"]
    assert result["status"] == "configured" and result["host_verified"] is False
    entry = entry_for(repository, target)
    assert entry["args"][-2:] == ["--root", str(repository)]
    assert "${workspaceFolder}" not in entry["args"]
    assert entry["args"][entry["args"].index("--model-source") + 1] == "local"
    assert entry["args"][entry["args"].index("--engine") + 1] == "rules"
    if target == "warp":
        assert entry["working_directory"] == str(repository)
        assert "File-based MCP Servers" in result["next_action"]
        assert not (repository / ".warp").exists()
    if target == "codex":
        assert entry["cwd"] == str(repository) and "trust" in result["next_action"]
    if target == "windsurf":
        assert "legacy Cascade" in result["next_action"]
        assert not (isolated_home / ".codeium").exists()
    configured = setup.EDITOR_SETUP[target].project_config
    for editor in setup.EDITOR_SETUP.values():
        if editor.project_config != configured:
            assert not (repository / editor.project_config).exists()
    before = {path: (Path(path).read_bytes(), Path(path).stat().st_mode)
              for path in result["changed_files"]}
    repeated = setup.configure_project(target, repository)
    assert repeated["status"] == "unchanged" and repeated["changed_files"] == []
    assert all((Path(path).read_bytes(), Path(path).stat().st_mode) == value
               for path, value in before.items())
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("target", setup.EDITORS)
def test_exact_nested_project_is_not_silently_promoted_to_git_root(repository, target):
    nested = repository / "packages" / "app with spaces"
    nested.mkdir(parents=True)
    result = setup.configure_project(target, nested)
    assert result["project"] == str(nested)
    assert all(Path(path).is_relative_to(nested) for path in result["changed_files"])
    assert entry_for(nested, target)["args"][-2:] == ["--root", str(nested)]
    assert not (repository / setup.EDITOR_SETUP[target].project_config).exists()


@pytest.mark.parametrize("target", setup.EDITORS)
def test_guided_setup_appends_managed_guidance_without_replacing_user_rules(repository, target):
    path = setup.effective_rule_path(repository, target)
    path.parent.mkdir(parents=True, exist_ok=True)
    original = b"# User guidance\r\n\r\nKeep fixture-private-guidance.\r\n"
    path.write_bytes(original)
    path.chmod(0o640)
    setup.configure_project(target, repository)
    assert path.read_bytes().startswith(original)
    assert path.read_text().count(setup.RULE_START) == 1
    assert path.stat().st_mode & 0o777 == 0o640
    assert b"\n" not in path.read_bytes().replace(b"\r\n", b"")


@pytest.mark.parametrize("override", ["# Effective override\n", "", " \n"])
def test_codex_respects_nonempty_override_precedence(repository, override):
    agents = repository / "AGENTS.md"
    agents.write_text("# Existing agents\n")
    selected = repository / "AGENTS.override.md"
    selected.write_text(override)
    result = setup.configure_project("codex", repository)
    effective = selected if override.strip() else agents
    preserved = agents if override.strip() else selected
    assert str(effective) in result["changed_files"] and str(preserved) not in result["changed_files"]
    assert setup.RULE_TEXT in effective.read_text()
    assert preserved.read_text() == ("# Existing agents\n" if override.strip() else override)


def test_codex_toml_preserves_comments_unrelated_tables_modes_and_host_policies(repository, isolated_home):
    path = repository / ".codex" / "config.toml"
    path.parent.mkdir()
    before = (
        '# fixture-private-comment\nmodel = "chosen-model" # preserve inline comment\n'
        'approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n\n'
        '[mcp_servers.other] # preserve this table\ncommand = "unrelated"\n'
        'args = ["fixture-private-argument"]\n\n'
        '[mcp_servers.polaris]\ncommand = "/old/runtime/bin/polaris" # old command note\n'
        'args = ["mcp", "--no-external-analyzers", "--model-source", "local"]\n'
        'enabled = false # remain disabled\n'
        'default_tools_approval_mode = "prompt"\ndisabled_tools = ["assess"]\n\n'
        '[mcp_servers.polaris.env]\nANY_NAME = "fixture-private-value" # keep env note\n\n'
        '[mcp_servers.polaris.tools.review_changes]\napproval_mode = "prompt"\n\n'
        '[unrelated]\nkeep = "literal # content" # keep final comment\n'
    )
    path.write_text(before)
    path.chmod(0o640)
    setup.configure_project("codex", repository)
    after = path.read_text()
    data = tomllib.loads(after)
    assert data["approval_policy"] == "on-request" and data["sandbox_mode"] == "workspace-write"
    assert data["mcp_servers"]["other"] == tomllib.loads(before)["mcp_servers"]["other"]
    entry = data["mcp_servers"]["polaris"]
    assert entry["enabled"] is False and entry["disabled_tools"] == ["assess"]
    assert entry["default_tools_approval_mode"] == "prompt"
    assert entry["tools"]["review_changes"]["approval_mode"] == "prompt"
    assert "--no-external-analyzers" in entry["args"]
    assert entry["env"]["ANY_NAME"] == "fixture-private-value"
    for fragment in ("# fixture-private-comment", "# preserve inline comment", "# preserve this table",
                     "# old command note", "# remain disabled", "# keep env note", "# keep final comment",
                     '[unrelated]\nkeep = "literal # content"'):
        assert fragment in after
    assert path.stat().st_mode & 0o777 == 0o640
    backups = list((isolated_home / ".polaris" / "backups").rglob("*config.toml"))
    assert len(backups) == 1 and backups[0].read_text() == before
    assert backups[0].stat().st_mode & 0o777 == 0o600
    assert backups[0].parent.stat().st_mode & 0o777 == 0o700
    assert setup.configure_project("codex", repository)["status"] == "unchanged"
    assert path.read_text() == after


@pytest.mark.parametrize("original", [
    '# comment\nmcp_servers = { other = { command = "unrelated", args = ["value"] } }\n',
    '# comment\nmcp_servers.other.command = "unrelated"\n',
    '# comment\n["mcp_servers"."other"]\ncommand = "unrelated"\n',
    '# comment\n[mcp_servers.other.env]\nVALUE = "fixture-private"\n[mcp_servers.other]\ncommand = "unrelated"\n',
])
def test_codex_supported_toml_shapes_remain_semantically_intact(repository, original):
    path = repository / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text(original)
    previous = tomllib.loads(original)
    setup.configure_project("codex", repository)
    after = tomllib.loads(path.read_text())
    assert after["mcp_servers"]["other"] == previous["mcp_servers"]["other"]
    assert "# comment" in path.read_text()


@pytest.mark.parametrize("target,text", [
    ("warp", '{"mcpServers": {}, "mcpServers": {"fixture-private-key": {}}}'),
    ("cursor", '{"mcpServers": {"other": {"command": "a", "command": "b"}}}'),
    ("claude-code", '{"mcpServers": {"polaris": null}}'),
    ("vscode", '{"servers": {}, "value": NaN}'),
    ("vscode", '{"servers": {}, "value": 1e400}'),
    ("warp", '{"mcpServers": {}, "value": -1e400}'),
    ("windsurf", '{"mcpServers": {}, "value": Infinity}'),
    ("codex", '[mcp_servers]\n[mcp_servers]\n'),
    ("codex", '[mcp_servers.other]\ncommand = "a"\ncommand = "fixture-private-value"\n'),
    ("codex", 'mcp_servers = [{ command = "a" }]\n'),
])
def test_ambiguous_configuration_refuses_all_writes_without_exposing_values(repository, target, text, capsys):
    path = repository / setup.EDITOR_SETUP[target].project_config
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    with pytest.raises((setup.SetupProblem, setup.Refused, IntegrationProblem)) as problem:
        setup.configure_project(target, repository)
    assert "fixture-private" not in str(problem.value)
    assert path.read_text() == text
    assert not setup.effective_rule_path(repository, target).exists()
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize("wrapper", ["servers", "mcp_servers"])
def test_warp_refuses_native_import_wrappers_at_the_discovery_path(repository, wrapper):
    path = repository / ".mcp.json"
    original = json.dumps({wrapper: {"other": {"command": "other"}}})
    path.write_text(original)
    with pytest.raises(setup.SetupProblem, match="Claude-compatible"):
        setup.configure_project("warp", repository)
    assert path.read_text() == original and not (repository / "AGENTS.md").exists()


@pytest.mark.parametrize("target", ["warp", "codex"])
def test_cli_previews_never_expose_unrelated_keys_values_or_comments(repository, target, capsys):
    path = repository / setup.EDITOR_SETUP[target].project_config
    path.parent.mkdir(parents=True, exist_ok=True)
    if target == "codex":
        path.write_text('# fixture-private-comment\n["fixture-private-key"]\nvalue = "fixture-private-value"\n')
    else:
        path.write_text('{"fixture-private-key": "fixture-private-value", "mcpServers": {}}')
    assert main(["setup", target, "--project", str(repository), "--dry-run"]) == 0
    captured = capsys.readouterr()
    assert "fixture-private" not in captured.out + captured.err


@pytest.mark.parametrize("target", setup.EDITORS)
def test_remote_setup_is_explicit_and_pins_saved_credentials_and_approved_origin(repository, target):
    result = setup.configure_project(target, repository, model_source="remote",
                                     api_url="https://approved.example.test", engine="hybrid")
    entry = entry_for(repository, target)
    assert entry["env"] == {
        "POLARIS_CREDENTIAL_SOURCE": "file",
        "POLARIS_EXPECTED_API_URL": "https://approved.example.test",
    }
    assert entry["args"][entry["args"].index("--model-source") + 1] == "remote"
    assert result["model_source"] == "remote" and result["host_verified"] is False
    assert "POLARIS_API_KEY" not in json.dumps(entry)


def test_remote_setup_requires_origin_and_local_setup_rejects_an_origin(repository):
    with pytest.raises(setup.SetupProblem, match="origin"):
        setup.configure_project("warp", repository, model_source="remote")
    with pytest.raises(setup.SetupProblem, match="explicit remote"):
        setup.configure_project("warp", repository, api_url="https://approved.example.test")
    assert not (repository / ".mcp.json").exists()


def test_old_versioned_bootstrap_can_be_updated_without_executing_it(repository):
    command = setup.polaris_command()
    command[-1] = ("import sys; sys.argv[0] = 'polaris'; sys.path.insert(0, '/old/version/site-packages'); "
                   "from polaris.cli import main; sys.exit(main())")
    path = repository / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {"polaris": {
        "command": command[0], "args": [*command[1:], "mcp", "--root", str(repository)],
        "disabled": True, "disabledTools": ["assess"],
    }}}))
    setup.configure_project("warp", repository)
    entry = entry_for(repository, "warp")
    assert entry["args"][:4] == setup.polaris_command()[1:]
    assert entry["disabled"] is True and entry["disabledTools"] == ["assess"]
    command[-1] += "; print('not an owned bootstrap')"
    assert not setup.is_polaris_entry({"command": command[0], "args": [*command[1:], "mcp"]})


@pytest.mark.parametrize("target", setup.EDITORS)
def test_generated_configuration_launches_bound_protocol_from_unrelated_cwd(repository, isolated_home, target):
    pytest.importorskip("mcp")
    import anyio
    from mcp import Client, StdioServerParameters

    setup.configure_project(target, repository)
    entry = entry_for(repository, target)
    environment = {**offline_environment(isolated_home), "CLAUDE_PROJECT_DIR": str(isolated_home),
                   "POLARIS_API_KEY": "fixture-ambient-key", "POLARIS_API_URL": "https://ambient.example.test"}
    parameters = StdioServerParameters(command=entry["command"], args=entry["args"],
                                       env=environment, cwd=str(isolated_home))

    async def inspect():
        with anyio.fail_after(15):
            async with Client(parameters) as client:
                return await client.call_tool("capabilities", {})

    result = anyio.run(inspect)
    assert not result.is_error
    assert result.structured_content["project_root"] == str(repository)
    assert result.structured_content["model"]["loaded"] is False
    assert "fixture-ambient-key" not in json.dumps(result.structured_content)
    assert not (repository / ".git" / "polaris-agent").exists()


@pytest.mark.parametrize("value,expected", [
    ("HTTPS://Approved.Example.Test:443/", "https://approved.example.test"),
    ("https://[0:0:0:0:0:0:0:1]:443/", "https://[::1]"),
    ("http://127.0.0.1:80/", "http://127.0.0.1"),
    ("http://[::1]:8780/", "http://[::1]:8780"),
])
def test_remote_origin_is_canonical_and_ambient_credentials_are_not_copied(repository, monkeypatch, value, expected):
    monkeypatch.setenv("POLARIS_API_KEY", "fixture-private-ambient-key")
    monkeypatch.setenv("POLARIS_API_URL", "https://ambient.example.test")
    setup.configure_project("warp", repository, model_source="remote", api_url=value)
    entry = entry_for(repository, "warp")
    assert entry["env"]["POLARIS_EXPECTED_API_URL"] == expected
    assert entry["env"]["POLARIS_CREDENTIAL_SOURCE"] == "file"
    assert "fixture-private-ambient-key" not in json.dumps(entry)
    assert "ambient.example.test" not in json.dumps(entry)


@pytest.mark.parametrize("value", [
    "https://user:fixture-private@api.example.test", "https://api.example.test/?fixture-private",
    "https://api.example.test/#fixture-private", "https://api.example.test/path",
    "https://api.example.test?", "https://api.example.test#", "https://api.example.test:",
    "https://api.example.test:99999", "https://api.example.test\\@other.example.test",
    "https://api.example.test\n", "http://api.example.test", "http://localhost:8780",
])
def test_invalid_remote_origin_never_writes_or_echoes_url(repository, capsys, value):
    with pytest.raises(setup.SetupProblem) as problem:
        setup.configure_project("warp", repository, model_source="remote", api_url=value)
    assert "fixture-private" not in str(problem.value)
    assert not (repository / ".mcp.json").exists() and not (repository / "AGENTS.md").exists()
    assert capsys.readouterr() == ("", "")


def test_remote_codex_merge_retains_unrelated_environment_comments_and_policies(repository):
    path = repository / ".codex" / "config.toml"
    path.parent.mkdir()
    path.write_text(
        '[mcp_servers.polaris]\ncommand = "polaris"\nargs = ["mcp"]\n'
        'enabled = false\n[mcp_servers.polaris.env]\n'
        'KEEP = "fixture-private-value" # private comment retained, never previewed\n'
        'POLARIS_CREDENTIAL_SOURCE = "environment" # selection note\n'
    )
    setup.configure_project("codex", repository, model_source="remote", api_url="https://approved.example.test")
    entry = entry_for(repository, "codex")
    assert entry["env"]["KEEP"] == "fixture-private-value" and entry["enabled"] is False
    assert entry["env"]["POLARIS_CREDENTIAL_SOURCE"] == "file"
    assert "# private comment retained, never previewed" in path.read_text()
    assert "# selection note" in path.read_text()
