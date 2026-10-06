"""Offline contract tests for the public GitHub Action (nothing is run on GitHub).

In the private repository the action lives at packaging/public-action/action.yml (the root
action.yml is the legacy private one). In the public repository it is the root action.yml.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

import pytest

from polaris import cli

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "packaging" / "public-action" / "action.yml"
ACTION = SOURCE if SOURCE.is_file() else ROOT / "action.yml"
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
SAMPLE = {"RUNNER_TEMP": "/runner/temp", "GITHUB_WORKSPACE": "/workspace", "BASE_SHA": "a" * 40,
          "HEAD_SHA": "b" * 40, "REPOSITORY": "acme/app", "PR_NUMBER": "7", "POLARIS_FAIL_ON": "findings"}


def action() -> dict:
    return yaml.safe_load(ACTION.read_text())


def steps() -> list[dict]:
    return action()["runs"]["steps"]


def polaris_command(script: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", script)
    line = next(item.strip() for item in joined.splitlines() if "-m polaris" in item)
    words = shlex.split(re.sub(r"\$\{?([A-Z_]+)\}?", lambda match: SAMPLE[match.group(1)], line))
    assert words[:4] == ["/runner/temp/polaris-env/bin/python", "-I", "-m", "polaris"]
    return words[4:]


def test_it_is_a_composite_action_with_marketplace_metadata():
    data = action()
    assert data["runs"]["using"] == "composite"
    assert data["name"] and len(data["description"]) <= 125 + 100  # a short, plain sentence
    assert data["branding"]["icon"] and data["branding"]["color"]
    assert set(data["inputs"]) == {"mode", "version", "fail-on", "token"}
    assert data["inputs"]["mode"]["required"] is True
    assert data["inputs"]["fail-on"]["default"] == "never", "advice by default, never a surprise red check"


def test_the_default_version_is_the_version_of_this_release():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert action()["inputs"]["version"]["default"] == project["version"], (
        "bump the action's default version with every release")


def test_every_action_is_pinned_and_no_expression_reaches_a_script():
    for step in steps():
        if "uses" in step:
            assert PINNED.match(step["uses"]), f"{step['uses']} isn't pinned to a commit"
        if "run" in step:
            assert "${{" not in step["run"], f"{step.get('name')} interpolates into its script"
            assert step["shell"] == "bash"
        assert not step.get("continue-on-error")


def test_each_mode_runs_only_its_own_steps():
    by_mode = {"analyze": [], "publish": []}
    for step in steps():
        condition = step.get("if", "")
        for mode in by_mode:
            if f"inputs.mode == '{mode}'" in condition:
                by_mode[mode].append(step)
    analyze_text = str(by_mode["analyze"])
    publish_text = str(by_mode["publish"])
    assert "actions/checkout@" in analyze_text and "pr plan" in analyze_text
    assert "actions/upload-artifact@" in analyze_text
    assert "actions/download-artifact@" in publish_text and "pr publish" in publish_text
    assert "actions/checkout@" not in publish_text, "the job holding the write token reads no repository"
    assert "pr publish" not in analyze_text and "pr plan" not in publish_text


def test_the_pull_request_is_fetched_as_data_and_never_checked_out():
    (checkout,) = [step for step in steps() if step.get("uses", "").startswith("actions/checkout@")]
    assert checkout["with"]["persist-credentials"] is False and "ref" not in checkout["with"]
    fetch = next(step for step in steps() if "git fetch" in step.get("run", ""))
    assert 'echo "::add-mask::$auth"' in fetch["run"] and "GIT_CONFIG_VALUE_0" in fetch["run"]
    assert "refs/pull/$PR_NUMBER/head" in fetch["run"] and '= "$HEAD_SHA"' in fetch["run"]
    text = ACTION.read_text()
    assert "git checkout" not in text.replace("actions/checkout", "") and "git worktree" not in text


def test_polaris_is_installed_outside_the_repository_at_an_exact_version():
    (install,) = [step for step in steps() if "uv pip install" in step.get("run", "")]
    assert install["working-directory"] == "${{ runner.temp }}"
    assert install["env"]["POLARIS_VERSION"] == "${{ inputs.version }}"
    assert install["run"].count("--no-config") == 2
    assert '"theovex-polaris==$POLARIS_VERSION"' in install["run"]
    (check,) = [step for step in steps() if step.get("name", "").startswith("Check the inputs")]
    script = check["run"]
    assert "analyze | publish" in script and "never | findings | incomplete" in script
    assert "grep -Eq" in script
    pattern = re.search(r"grep -Eq '([^']+)'", script).group(1)
    for good in ("0.4.0", "1.2.3", "0.4.1rc1", "0.4.0.post1"):
        assert re.search(pattern, good), good
    for bad in ("0.4", "latest", "0.4.0 --index-url https://evil.example", "0.4.0;id", "$(id)", ""):
        assert not re.search(pattern, bad), bad


def test_commands_parse_and_bind_to_the_event_not_to_the_plan():
    plan_step = next(step for step in steps() if "pr plan" in step.get("run", ""))
    plan = cli.parser().parse_args(polaris_command(plan_step["run"]))
    assert (plan.command, plan.pr_command) == ("pr", "plan") and plan.no_external_analyzers
    assert (plan.base, plan.head, plan.repository, plan.pull_request) == ("a" * 40, "b" * 40, "acme/app", 7)
    assert plan_step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert "GITHUB_TOKEN" not in str(plan_step.get("env")), "the analysis step never holds a token"
    publish_step = next(step for step in steps() if "pr publish" in step.get("run", ""))
    publish = cli.parser().parse_args(polaris_command(publish_step["run"]))
    assert (publish.pr_command, publish.head, publish.pull_request) == ("publish", "b" * 40, 7)
    assert publish.fail_on == "findings" and publish_step["env"]["POLARIS_FAIL_ON"] == "${{ inputs.fail-on }}"
    assert publish_step["env"]["GITHUB_TOKEN"] == "${{ inputs.token }}"
    assert publish_step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert action()["inputs"]["token"]["default"] == "${{ github.token }}"


def test_plans_are_kept_for_days_not_weeks():
    (upload,) = [step for step in steps() if step.get("uses", "").startswith("actions/upload-artifact@")]
    assert upload["with"]["retention-days"] <= 7 and upload["with"]["if-no-files-found"] == "error"
