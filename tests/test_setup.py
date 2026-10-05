"""`polaris setup` tests in temporary home and project folders; nothing real is touched."""

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from polaris.cli import main
from polaris.integrations._safe import module_command, offline_environment, run_bounded
from polaris.integrations.setup import HOOK_MARKER, RULE_END, RULE_START, RULE_TEXT

HEADER = "import os, subprocess\nfrom flask import request\n\n"


@pytest.fixture
def home(tmp_path, monkeypatch):
    folder = tmp_path / "home"
    folder.mkdir()
    for name in ("XDG_CONFIG_HOME", "APPDATA", "POLARIS_MODEL", "CLAUDE_PROJECT_DIR"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(folder))
    monkeypatch.setenv("POLARIS_HOME", str(folder / ".polaris"))
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(folder / ".gitconfig"))
    return folder


def git(root, *args, check=True):
    return subprocess.run(["git", "-C", str(root), *args], check=check, capture_output=True, text=True,
                          env={**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"})


@pytest.fixture
def project(tmp_path, home):
    root = tmp_path / "project"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


def setup(*args, project=None):
    return main(["setup", *args, *(["--project", str(project)] if project is not None else [])])


def test_dry_run_shows_the_change_and_writes_nothing(project, capsys):
    assert setup("cursor", "--rule", "--dry-run", project=project) == 0
    out = capsys.readouterr().out
    assert "create .cursor/mcp.json: add MCP server \"polaris\"" in out
    assert '+  "mcpServers": {' in out and "Dry run: nothing was written." in out
    assert not (project / ".cursor").exists()


def test_cursor_project_config_and_rule(project, capsys):
    assert setup("cursor", "--rule", project=project) == 0
    entry = json.loads((project / ".cursor" / "mcp.json").read_text())["mcpServers"]["polaris"]
    assert entry["type"] == "stdio" and entry["command"] == sys.executable
    assert entry["args"] == [*module_command("polaris.cli")[1:], "mcp", "--model-source", "local",
                             "--root", str(project)]
    rule = (project / ".cursor" / "rules" / "polaris.mdc").read_text()
    assert rule.startswith("---\n") and "alwaysApply: true" in rule and RULE_TEXT in rule
    out = capsys.readouterr().out
    assert "Next: Restart Cursor" in out and "--command polaris" in out
    assert setup("cursor", "--rule", project=project) == 0
    assert "Already set up; nothing to change." in capsys.readouterr().out


@pytest.mark.parametrize(("target", "config", "key", "rule", "root_argument"), [
    ("cursor", ".cursor/mcp.json", "mcpServers", ".cursor/rules/polaris.mdc", True),
    ("claude-code", ".mcp.json", "mcpServers", ".claude/rules/polaris.md", True),
    ("vscode", ".vscode/mcp.json", "servers", ".github/instructions/polaris.instructions.md", True),
    ("windsurf", ".devin/mcp_config.json", "mcpServers", ".devin/rules/polaris.md", True),
])
def test_project_setup_writes_each_editors_documented_files(project, target, config, key, rule, root_argument):
    assert setup(target, "--rule", "--command", "polaris", project=project) == 0
    entry = json.loads((project / config).read_text())[key]["polaris"]
    assert entry["command"] == "polaris" and entry["args"][0] == "mcp"
    assert ("--root" in entry["args"]) is root_argument
    assert ("type" in entry) is (target != "windsurf")
    assert RULE_TEXT in (project / rule).read_text()


def test_global_setup_uses_each_editors_user_files(home, tmp_path, monkeypatch):
    claude = home / ".claude.json"
    claude.write_text(json.dumps({"numStartups": 3, "projects": {"/x": {"mcpServers": {}}}}, indent=2))
    assert setup("claude-code", "--global", "--rule") == 0
    data = json.loads(claude.read_text())
    assert data["numStartups"] == 3 and data["projects"] == {"/x": {"mcpServers": {}}}
    assert "--root" not in data["mcpServers"]["polaris"]["args"]
    assert RULE_TEXT in (home / ".claude" / "rules" / "polaris.md").read_text()
    assert setup("cursor", "--global") == 0
    assert "polaris" in json.loads((home / ".cursor" / "mcp.json").read_text())["mcpServers"]
    assert setup("vscode", "--global") == 0
    user = (home / "Library" / "Application Support" / "Code" / "User" if sys.platform == "darwin"
            else home / ".config" / "Code" / "User")
    assert "polaris" in json.loads((user / "mcp.json").read_text())["servers"]
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    (home / ".codeium" / "windsurf").mkdir(parents=True)
    assert setup("windsurf", "--global", "--rule") == 0
    for path in (tmp_path / "xdg" / "devin" / "mcp_config.json", home / ".codeium" / "windsurf" / "mcp_config.json"):
        assert "polaris" in json.loads(path.read_text())["mcpServers"]
    assert RULE_TEXT in (home / ".devin" / "rules" / "polaris.md").read_text()


def test_merging_keeps_unrelated_settings_and_backs_up_the_old_file(home, project):
    path = project / ".cursor" / "mcp.json"
    path.parent.mkdir()
    original = {"mcpServers": {"other": {"command": "npx", "args": ["-y", "other"]}}, "unrelated": {"keep": [1, 2]}}
    path.write_text(json.dumps(original, indent=4) + "\n")
    assert setup("cursor", project=project) == 0
    merged = json.loads(path.read_text())
    assert merged["unrelated"] == {"keep": [1, 2]} and merged["mcpServers"]["other"] == original["mcpServers"]["other"]
    assert list(merged["mcpServers"]) == ["other", "polaris"]
    assert path.read_text().startswith('{\n    "mcpServers": {\n        "other"')
    backups = list((home / ".polaris" / "backups").rglob("*mcp.json"))
    assert len(backups) == 1 and json.loads(backups[0].read_text()) == original


def test_a_different_server_named_polaris_is_never_replaced_without_force(home, project, capsys):
    path = project / ".mcp.json"
    unrelated = {"mcpServers": {"polaris": {"command": "/opt/someone-else/star-map", "args": ["serve"]}}}
    path.write_text(json.dumps(unrelated))
    assert setup("claude-code", project=project) == 1
    assert json.loads(path.read_text()) == unrelated and "nothing was written" in capsys.readouterr().err
    assert setup("claude-code", "--name", "polaris-review", project=project) == 0
    servers = json.loads(path.read_text())["mcpServers"]
    assert servers["polaris"] == unrelated["mcpServers"]["polaris"] and "mcp" in servers["polaris-review"]["args"]
    assert setup("claude-code", "--force", project=project) == 0
    assert "mcp" in json.loads(path.read_text())["mcpServers"]["polaris"]["args"]


def test_our_own_entry_is_updated_when_the_executable_moves(project, capsys):
    assert setup("claude-code", "--command", "/old/venv/bin/polaris", project=project) == 0
    assert setup("claude-code", project=project) == 0
    assert "update MCP server \"polaris\"" in capsys.readouterr().out
    assert json.loads((project / ".mcp.json").read_text())["mcpServers"]["polaris"]["command"] == sys.executable


def test_files_polaris_cannot_safely_rewrite_are_left_alone(project, tmp_path, capsys):
    commented = project / ".vscode" / "mcp.json"
    commented.parent.mkdir()
    commented.write_text('{\n  // my servers\n  "servers": {}\n}\n')
    assert setup("vscode", project=project) == 2
    assert "may contain comments" in capsys.readouterr().err and "// my servers" in commented.read_text()
    real = tmp_path / "shared.json"
    real.write_text("{}")
    (project / ".mcp.json").symlink_to(real)
    assert setup("claude-code", project=project) == 2
    assert "symbolic link" in capsys.readouterr().err and real.read_text() == "{}"
    rule = project / ".claude" / "rules" / "polaris.md"
    rule.parent.mkdir(parents=True)
    rule.write_text("my own words\n")
    (project / ".mcp.json").unlink()
    assert setup("claude-code", "--rule", project=project) == 0
    assert rule.read_text() == "my own words\n" and "Kept your existing" in capsys.readouterr().out


def test_git_hook_install_refusal_force_and_backup(project, capsys):
    assert setup("git-hook", "--dry-run", project=project) == 0
    hook = project / ".git" / "hooks" / "pre-commit"
    assert not hook.exists()
    assert setup("git-hook", project=project) == 0
    text = hook.read_text()
    assert text.startswith("#!/bin/sh\n") and HOOK_MARKER in text and "review --staged" in text
    assert os.access(hook, os.X_OK)
    assert setup("git-hook", project=project) == 0
    assert "Already set up" in capsys.readouterr().out
    hook.write_text("#!/bin/sh\necho mine\n")
    assert setup("git-hook", project=project) == 1
    assert hook.read_text() == "#!/bin/sh\necho mine\n"
    assert setup("git-hook", "--force", project=project) == 0
    assert (hook.parent / "pre-commit.polaris-backup").read_text() == "#!/bin/sh\necho mine\n"
    assert HOOK_MARKER in hook.read_text()
    assert setup("git-hook", "--fail-on", "surprise", project=project) == 2
    assert setup("git-hook", "--global", project=project) == 2


def test_git_hook_follows_core_hooks_path_but_not_into_shared_folders(project, tmp_path, capsys):
    git(project, "config", "core.hooksPath", ".githooks")
    assert setup("git-hook", project=project) == 0
    assert HOOK_MARKER in (project / ".githooks" / "pre-commit").read_text()
    shared = tmp_path / "shared-hooks"
    git(project, "config", "core.hooksPath", str(shared))
    assert setup("git-hook", project=project) == 1
    assert "other repositories may share" in capsys.readouterr().err and not shared.exists()


def test_git_hook_outside_a_repository_is_explained(tmp_path, home, capsys):
    plain = tmp_path / "plain"
    plain.mkdir()
    assert setup("git-hook", project=plain) == 2
    assert "isn't a git repository" in capsys.readouterr().err


def test_the_installed_hook_blocks_flagged_commits_and_skips_without_a_model(project, capsys):
    command = shlex.join([sys.executable, "-m", "polaris"])
    assert setup("git-hook", "--engine", "rules", "--command", command, project=project) == 0
    (project / "safe.py").write_text("def add(a, b):\n    return a + b\n")
    git(project, "add", "safe.py")
    assert git(project, "commit", "-q", "-m", "safe", check=False).returncode == 0
    (project / "ping.py").write_text(HEADER + "def ping(host):\n    os.system('ping -c 1 ' + host)\n")
    git(project, "add", "ping.py")
    blocked = git(project, "commit", "-q", "-m", "risky", check=False)
    assert blocked.returncode != 0 and "FLAGGED" in blocked.stdout + blocked.stderr
    # The default hybrid hook needs no model: the rules still stop the commit.
    assert setup("git-hook", "--force", "--command", command, project=project) == 0
    still_blocked = git(project, "commit", "-q", "-m", "hybrid", check=False)
    assert still_blocked.returncode != 0 and "FLAGGED" in still_blocked.stdout + still_blocked.stderr
    # A model-only hook lets the commit through (with a warning) when no model is installed.
    assert setup("git-hook", "--force", "--engine", "model", "--command", command, project=project) == 0
    allowed = git(project, "commit", "-q", "-m", "no model", check=False)
    assert allowed.returncode == 0 and "wasn't reviewed" in allowed.stderr


def test_a_project_config_starts_a_working_mcp_server(project, tmp_path):
    pytest.importorskip("mcp")
    import anyio
    from mcp import Client, StdioServerParameters

    assert setup("cursor", "--engine", "rules", project=project) == 0
    entry = json.loads((project / ".cursor" / "mcp.json").read_text())["mcpServers"]["polaris"]
    args = [str(project) if part == "${workspaceFolder}" else part for part in entry["args"]]
    parameters = StdioServerParameters(command=entry["command"], args=args,
                                       env={"POLARIS_HOME": str(tmp_path / "polaris-home")})

    async def tools():
        async with Client(parameters) as client:
            return [tool.name for tool in (await client.list_tools()).tools]

    assert anyio.run(tools) == ["polaris_check", "polaris_explain", "polaris_fix"]
    assert Path(entry["command"]).exists()


def test_warp_defaults_to_managed_rules_and_an_explicit_local_root(project, capsys):
    agents = project / "AGENTS.md"
    original = "# Next.js project\n\nKeep the user's framework guidance.\n"
    agents.write_text(original)
    assert setup("warp", "--engine", "rules", project=project) == 0
    config = project / ".mcp.json"
    data = json.loads(config.read_text())
    entry = data["mcpServers"]["polaris"]
    assert entry["working_directory"] == str(project)
    assert entry["args"][-2:] == ["--root", str(project)]
    assert entry["args"][entry["args"].index("--model-source") + 1] == "local"
    assert agents.read_text().startswith(original)
    assert agents.read_text().count(RULE_START) == 1 and RULE_TEXT in agents.read_text()
    first = agents.read_bytes(), config.read_bytes()
    assert setup("warp", "--engine", "rules", project=project) == 0
    assert (agents.read_bytes(), config.read_bytes()) == first
    assert "Already set up" in capsys.readouterr().out


def test_warp_uses_effective_warp_file_and_preserves_surrounding_bytes(project):
    agents = project / "AGENTS.md"
    agents.write_text("# Keep AGENTS untouched\n")
    path = project / "WARP.md"
    before = "# Existing rules\r\n\r\n" + RULE_START + "\r\nold rule\r\n" + RULE_END + "\r\nFooter\r\n"
    path.write_bytes(before.encode())
    assert setup("warp", project=project) == 0
    after = path.read_bytes()
    assert after.startswith(b"# Existing rules\r\n\r\n") and after.endswith(b"\r\nFooter\r\n")
    assert agents.read_text() == "# Keep AGENTS untouched\n"
    assert b"\n" not in after.replace(b"\r\n", b"")
    assert setup("warp", project=project) == 0 and path.read_bytes() == after


@pytest.mark.parametrize("wrapper", ["mcpServers", "mcp_servers", "servers", "nested", "flat"])
def test_warp_leaves_legacy_manual_import_files_untouched(project, wrapper):
    entry = {"command": "/unrelated/program", "args": ["serve"], "env": {"ANY": "fixture-value"}}
    servers = {"other": entry}
    if wrapper == "nested":
        original = {"mcp": {"servers": servers, "keep": True}, "unrelated": 9}
    elif wrapper == "flat":
        original = servers
    else:
        original = {wrapper: servers, "unrelated": 9}
    path = project / ".warp" / ".mcp.json"
    path.parent.mkdir()
    path.write_text(json.dumps(original))
    assert setup("warp", project=project) == 0
    assert json.loads(path.read_text()) == original
    discovered = json.loads((project / ".mcp.json").read_text())
    assert set(discovered) == {"mcpServers"}
    assert set(discovered["mcpServers"]) == {"polaris"}


def test_setup_previews_never_echo_arbitrary_adjacent_values_or_guidance(project, home, capsys):
    path = project / ".mcp.json"
    original = {"mcpServers": {"other": {"command": "fixture-command",
                 "env": {"ARBITRARY": "fixture-private-env", "UNNAMED": "fixture-other-env"},
                 "headers": {"X-Any": "fixture-private-header"}, "args": ["fixture-private-arg"]}},
                "arbitrary_setting": "fixture-private-setting"}
    path.write_text(json.dumps(original, indent=2))
    (project / "AGENTS.md").write_text("Keep fixture-private-guidance unchanged.\n")
    assert setup("warp", "--dry-run", project=project) == 0
    preview = capsys.readouterr()
    for value in ("fixture-private-env", "fixture-other-env", "fixture-private-header",
                  "fixture-private-arg", "fixture-private-setting", "fixture-private-guidance"):
        assert value not in preview.out + preview.err
    assert "<redacted>" in preview.out
    assert json.loads(path.read_text()) == original
    assert setup("warp", project=project) == 0
    assert json.loads(path.read_text())["mcpServers"]["other"] == original["mcpServers"]["other"]
    backups = [item for item in (home / ".polaris" / "backups").rglob("*") if item.is_file()]
    assert backups and all(item.stat().st_mode & 0o777 == 0o600 for item in backups)


@pytest.mark.parametrize("target,folder", [("warp", ".mcp.json"), ("cursor", ".cursor"), ("claude-code", ".claude")])
def test_setup_refuses_symlink_ancestors_even_with_force(project, tmp_path, target, folder):
    external = tmp_path / "outside"
    external.mkdir()
    (project / folder).symlink_to(external, target_is_directory=True)
    assert setup(target, "--rule", "--force", project=project) == 2
    assert list(external.iterdir()) == []
    assert not (project / ".mcp.json").exists() or (project / ".mcp.json").is_symlink()


def test_setup_rejects_symlinked_project_and_backup_ancestors(project, home, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(project, target_is_directory=True)
    assert setup("warp", project=alias) == 2
    assert not (project / ".mcp.json").exists()
    assert setup("warp", project=project) == 0
    outside = tmp_path / "backup-outside"
    outside.mkdir()
    (home / ".polaris").mkdir(exist_ok=True)
    (home / ".polaris" / "backups").symlink_to(outside, target_is_directory=True)
    path = project / ".mcp.json"
    before = path.read_bytes()
    assert setup("warp", "--engine", "rules", project=project) == 2
    assert path.read_bytes() == before and not list(outside.iterdir())


def test_warp_refuses_ambiguous_managed_block_without_partial_setup(project):
    (project / "AGENTS.md").write_text(RULE_START + "\nunfinished\n")
    assert setup("warp", "--force", project=project) == 2
    assert not (project / ".mcp.json").exists()


@pytest.mark.parametrize("target,path,event,stop", [
    ("claude-code", ".claude/settings.json", "PostToolUse", "Stop"),
    ("cursor", ".cursor/hooks.json", "afterFileEdit", "stop"),
])
def test_opt_in_completion_hooks_preserve_unrelated_handlers_and_are_idempotent(project, target, path, event, stop):
    config = project / path
    config.parent.mkdir()
    unrelated = ({"matcher": "Edit", "hooks": [{"type": "command", "command": "unrelated-command"}]}
                 if target == "claude-code" else {"command": "unrelated-command", "timeout": 8})
    original = {"hooks": {event: [unrelated], "SessionStart": [{"custom": "keep"}]},
                "unrelated": {"keep": True}}
    if target == "cursor":
        original["version"] = 1
    config.write_text(json.dumps(original, indent=2))
    assert setup(target, "--hooks", project=project) == 0
    result = json.loads(config.read_text())
    assert result["hooks"][event][0] == unrelated
    assert result["hooks"]["SessionStart"] == [{"custom": "keep"}]
    assert result["unrelated"] == {"keep": True}
    handler = result["hooks"][stop][-1]
    if target == "claude-code":
        handler = handler["hooks"][0]
        assert handler["type"] == "command"
    else:
        assert handler["loop_limit"] == 3  # hand back what to fix now, a few rounds at most
    assert "agent-hook" in handler["command"] and "--root" in handler["command"]
    assert "--event check" in handler["command"]
    assert handler["timeout"] == 45
    before = config.read_bytes()
    assert setup(target, "--hooks", project=project) == 0
    assert config.read_bytes() == before


def test_hooks_are_never_added_implicitly_or_invented_for_warp(project):
    assert setup("claude-code", project=project) == 0
    assert not (project / ".claude" / "settings.json").exists()
    assert setup("warp", "--hooks", project=project) == 2
    assert setup("cursor", "--hooks", "--global", project=project) == 2


def test_invalid_hook_config_prevents_all_setup_writes(project):
    folder = project / ".claude"
    folder.mkdir()
    path = folder / "settings.json"
    path.write_text('{"hooks": {"Stop": "not-an-array"}}')
    assert setup("claude-code", "--hooks", project=project) == 2
    assert not (project / ".mcp.json").exists()


def test_strict_precommit_independently_requires_complete_workflow(project):
    assert setup("git-hook", "--required-review", "--command", "polaris", project=project) == 0
    text = (project / ".git" / "hooks" / "pre-commit").read_text()
    assert "workflow review --staged --require-complete --format json" in text
    assert "exit 0" not in text and "review.json" not in text
    assert setup("warp", "--required-review", project=project) == 2


def test_default_launch_does_not_import_project_python_or_inherited_pythonpath(project, home, monkeypatch):
    from polaris.integrations.setup import is_polaris_entry, polaris_command

    marker = project / "project-code-executed"
    for name in ("polaris.py", "sitecustomize.py"):
        (project / name).write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    monkeypatch.setenv("PYTHONPATH", str(project))
    command = polaris_command()
    result = run_bounded([*command, "--help"], cwd=project,
                         env={**offline_environment(home), "PYTHONPATH": str(project)}, timeout=10)
    assert result.returncode == 0 and b"usage: polaris" in result.stdout and not marker.exists()
    assert is_polaris_entry({"command": command[0], "args": [*command[1:], "mcp"]})
    assert not is_polaris_entry({"command": command[0], "args": ["-c", "arbitrary()", "-m", "polaris", "mcp"]})
    assert not is_polaris_entry({"command": "unrelated-python-wrapper", "args": ["-m", "polaris", "mcp"]})
    assert polaris_command("caller-trusted --argument value") == ["caller-trusted", "--argument", "value"]


def test_explicit_semgrep_is_validated_not_executed_and_passed_to_mcp_and_hooks(project, tmp_path):
    executable = tmp_path.resolve() / "semgrep-fixture"
    marker = tmp_path / "analyzer-executed"
    executable.write_text(f"#!/bin/sh\nprintf invoked > {shlex.quote(str(marker))}\n")
    executable.chmod(0o700)
    assert setup("cursor", "--hooks", "--semgrep", str(executable), project=project) == 0
    entry = json.loads((project / ".cursor" / "mcp.json").read_text())["mcpServers"]["polaris"]
    assert entry["args"][entry["args"].index("--semgrep") + 1] == str(executable)
    hook_path = project / ".cursor" / "hooks.json"
    for entries in json.loads(hook_path.read_text())["hooks"].values():
        call = shlex.split(entries[-1]["command"])
        assert call[call.index("--semgrep") + 1] == str(executable)
    previous = hook_path.read_bytes()
    assert setup("cursor", "--hooks", "--semgrep-executable", str(executable), project=project) == 0
    assert hook_path.read_bytes() == previous and not marker.exists()
    assert setup("git-hook", "--required-review", "--semgrep", str(executable), project=project) == 0
    assert "--semgrep" in (project / ".git" / "hooks" / "pre-commit").read_text()
    assert setup("git-hook", "--semgrep", str(executable), project=project) == 2
    assert not marker.exists()


def test_invalid_analyzer_paths_do_not_write_configuration(project, tmp_path):
    assert setup("warp", "--semgrep", "relative-semgrep", project=project) == 2
    executable = tmp_path.resolve() / "semgrep-fixture"
    executable.write_text("#!/bin/sh\nexit 0\n")
    assert setup("warp", "--semgrep", str(executable), project=project) == 2
    executable.chmod(0o700)
    alias = tmp_path / "semgrep-link"
    alias.symlink_to(executable)
    assert setup("warp", "--semgrep", str(alias), project=project) == 2
    assert not (project / ".mcp.json").exists() and not (project / "AGENTS.md").exists()


def test_custom_global_launch_arguments_are_not_printed(home, capsys):
    assert setup("claude-code", "--global", "--command", "polaris --custom fixture-private-launch-value") == 0
    captured = capsys.readouterr()
    assert "fixture-private-launch-value" not in captured.out + captured.err


def test_setup_refuses_symlinked_git_metadata_even_with_force(project):
    (project / ".git").rename(project / ".git-actual")
    (project / ".git").symlink_to(project / ".git-actual", target_is_directory=True)
    assert setup("warp", "--force", project=project) == 2
    assert setup("git-hook", "--force", project=project) == 2
    assert not (project / ".mcp.json").exists()


@pytest.mark.parametrize("target,path,event", [
    ("cursor", ".cursor/hooks.json", "stop"),
    ("claude-code", ".claude/settings.json", "Stop"),
])
def test_custom_hook_launches_are_idempotent_and_composite_existing_hooks_are_preserved(project, target, path, event):
    custom = "caller-trusted-wrapper --argument value"
    assert setup(target, "--hooks", "--command", custom, project=project) == 0
    config = project / path
    previous = config.read_bytes()
    assert setup(target, "--hooks", "--command", custom, project=project) == 0
    assert config.read_bytes() == previous
    combined = shlex.join(["polaris", "agent-hook", "--host", target, "--event", "stop",
                           "--root", str(project), "--timeout", "20"]) + " && unrelated-command"
    entry = ({"hooks": [{"type": "command", "command": combined}]} if target == "claude-code"
             else {"command": combined})
    data = json.loads(config.read_text())
    data["hooks"][event].insert(0, entry)
    config.write_text(json.dumps(data))
    assert setup(target, "--hooks", "--command", custom, project=project) == 0
    assert json.loads(config.read_text())["hooks"][event][0] == entry
