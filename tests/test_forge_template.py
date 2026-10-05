"""Offline contract tests for the pull-request review workflow template (nothing is run on GitHub)."""

from __future__ import annotations

import re
import shlex
from pathlib import Path

import pytest

from polaris import cli

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "ci" / "github" / "polaris-pr-review.yml"
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
SAMPLE = {"RUNNER_TEMP": "/runner/temp", "GITHUB_WORKSPACE": "/workspace", "BASE_SHA": "a" * 40,
          "HEAD_SHA": "b" * 40, "REPOSITORY": "acme/app", "PR_NUMBER": "7"}


def workflow() -> dict:
    return yaml.safe_load(TEMPLATE.read_text())


def polaris_command(script: str) -> list[str]:
    joined = re.sub(r"\\\n\s*", " ", script)
    line = next(item.strip() for item in joined.splitlines() if "-m polaris" in item)
    words = shlex.split(re.sub(r"\$\{?([A-Z_]+)\}?", lambda match: SAMPLE[match.group(1)], line))
    assert words[:4] == ["/runner/temp/polaris-env/bin/python", "-I", "-m", "polaris"]
    return words[4:]


def test_trigger_permissions_and_concurrency():
    template = workflow()
    assert set(template.get("on", template.get(True))) == {"pull_request_target"}
    assert template["permissions"] == {}
    assert template["concurrency"]["cancel-in-progress"] is True
    jobs = template["jobs"]
    assert jobs["analyze"]["permissions"] == {"contents": "read"}
    assert jobs["publish"]["permissions"] == {"contents": "read", "pull-requests": "write"}
    assert jobs["publish"]["needs"] == "analyze"
    assert "secrets." not in TEMPLATE.read_text(), "only the job token is used"


def test_every_action_is_pinned_and_no_expression_reaches_a_script():
    for name, job in workflow()["jobs"].items():
        assert job["timeout-minutes"] <= 15
        for step in job["steps"]:
            if "uses" in step:
                assert PINNED.match(step["uses"]), f"{name}: {step['uses']} isn't pinned to a commit"
            if "run" in step:
                assert "${{" not in step["run"], f"{name}: {step.get('name')} interpolates into its script"
            assert not step.get("continue-on-error")


def test_the_pull_request_is_fetched_as_data_and_never_checked_out():
    analyze, publish = workflow()["jobs"]["analyze"], workflow()["jobs"]["publish"]
    (checkout,) = [step for step in analyze["steps"] if step.get("uses", "").startswith("actions/checkout@")]
    assert checkout["with"]["persist-credentials"] is False and "ref" not in checkout["with"]
    assert not any(step.get("uses", "").startswith("actions/checkout@") for step in publish["steps"])
    fetch = next(step for step in analyze["steps"] if "git fetch" in step.get("run", ""))
    assert 'echo "::add-mask::$auth"' in fetch["run"] and "GIT_CONFIG_VALUE_0" in fetch["run"]
    assert "refs/pull/$PR_NUMBER/head" in fetch["run"] and '= "$HEAD_SHA"' in fetch["run"]
    assert "git checkout" not in TEMPLATE.read_text() and "git worktree" not in TEMPLATE.read_text()


def test_tools_are_installed_outside_the_repository_without_project_configuration():
    for job in workflow()["jobs"].values():
        installs = [step for step in job["steps"] if "uv pip install" in step.get("run", "")]
        assert len(installs) == 1
        step = installs[0]
        assert step["working-directory"] == "${{ runner.temp }}"
        assert step["env"]["POLARIS_PACKAGE"] == "${{ vars.POLARIS_PACKAGE }}"
        assert step["run"].count("--no-config") == 2 and 'if [ -z "$POLARIS_PACKAGE" ]' in step["run"]
        uploads = [item for item in job["steps"] if item.get("uses", "").startswith("actions/upload-artifact@")]
        assert all(item["with"]["retention-days"] <= 7 for item in uploads)


def test_commands_parse_and_bind_to_the_trusted_event():
    jobs = workflow()["jobs"]
    plan_step = next(step for step in jobs["analyze"]["steps"] if "pr plan" in step.get("run", ""))
    plan = cli.parser().parse_args(polaris_command(plan_step["run"]))
    assert (plan.command, plan.pr_command) == ("pr", "plan") and plan.no_external_analyzers
    assert (plan.base, plan.head, plan.repository, plan.pull_request) == ("a" * 40, "b" * 40, "acme/app", 7)
    assert plan_step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    publish_step = next(step for step in jobs["publish"]["steps"] if "pr publish" in step.get("run", ""))
    publish = cli.parser().parse_args(polaris_command(publish_step["run"]))
    assert (publish.pr_command, publish.head, publish.pull_request) == ("publish", "b" * 40, 7)
    assert publish_step["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
    assert publish_step["env"]["HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"
    assert "GITHUB_TOKEN" not in str(plan_step.get("env")), "the analysis step never holds a token"
