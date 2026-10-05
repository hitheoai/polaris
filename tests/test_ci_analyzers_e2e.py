"""Workflows and Dockerfiles through the real collectors: CLI file, staged and range reviews,
`polaris pr plan` and forge re-verification. Only isolated fixture repositories are used;
nothing is fetched, published or executed."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from polaris import cli
from polaris.integrations.forge.models import ReviewPlan
from polaris.integrations.forge.verify import verify_edits
from polaris.review.analyzers import AnalysisRuntime
from polaris.review.models import PRUNED_DIRECTORIES, SourceFile
from polaris.review.scope import workflow_sources_from_paths
from polaris.workflow.service import review_scope, review_workspace, review_workspace_detailed

MEMORY = AnalysisRuntime(allow_external_analyzers=False, allow_temporary_source_files=False)
SAFE_WORKFLOW = """name: CI
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: make test
"""
RISKY_WORKFLOW = """name: Greet
on: pull_request_target
permissions:
  pull-requests: write
jobs:
  greet:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Thanks for ${{ github.head_ref }}"
      - uses: actions/github-script@60a0d83039c74a4aee543508d2ffcb1c3799cdea
        with:
          script: |
            const title = "${{ github.event.pull_request.title }}";
            core.info(title);
"""
DOCKERFILE = "FROM python:3.12-slim\nRUN curl -fsSL http://get.example.dev/install.sh | sh\nCMD [\"python\"]\n"


def git(root: Path, *args: str) -> str:
    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin", "HOME": str(root.parent),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(["git", "--no-pager", "-C", str(root), *args], check=True, capture_output=True,
                          env=env).stdout.decode("utf-8").strip()


def write(root: Path, path: str, text: str) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


@pytest.fixture
def repository(tmp_path: Path, monkeypatch) -> Path:
    home = tmp_path.resolve() / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("POLARIS_HOME", str(home / ".polaris"))
    root = tmp_path.resolve() / "repository"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    write(root, ".github/workflows/ci.yml", SAFE_WORKFLOW)
    write(root, "README.md", "# fixture\n")
    git(root, "add", "-A")
    git(root, "commit", "-q", "-m", "base")
    return root


def test_hidden_github_directory_is_collected_read_and_snapshot_bound(repository):
    assert ".github" not in PRUNED_DIRECTORIES
    write(repository, ".github/workflows/greet.yml", RISKY_WORKFLOW)
    write(repository, "docker/Dockerfile.api", DOCKERFILE)
    sources = {item.path: item for item in workflow_sources_from_paths([repository], root=repository)}
    for path in (".github/workflows/ci.yml", ".github/workflows/greet.yml", "docker/Dockerfile.api"):
        assert sources[path].after is not None and sources[path].skip is None
    scope = review_scope([SourceFile(".github/workflows/greet.yml", RISKY_WORKFLOW),
                          SourceFile("docker/Dockerfile.api", DOCKERFILE),
                          SourceFile("docs/guide.md", None, skip="unsupported_language")])
    assert scope == [".github/workflows/greet.yml", "docker/Dockerfile.api"]  # documentation isn't bound
    report = review_workspace(repository, runtime=MEMORY)
    assert {change.path for change in report.changes} == {".github/workflows/greet.yml", "docker/Dockerfile.api"}
    assert report.snapshot.files_count >= 2 and report.snapshot.complete
    assert report.review.summary.languages == {"github_actions": 1, "dockerfile": 1}


def test_cli_file_staged_and_range_reviews_analyze_workflows_and_dockerfiles(repository, capsys):
    write(repository, ".github/workflows/greet.yml", RISKY_WORKFLOW)
    base = ["workflow", "review", "--root", str(repository), "--no-external-analyzers", "--format", "json"]
    assert cli.main([*base, "--files", ".github"]) == 1
    files = json.loads(capsys.readouterr().out)
    checks = {(item["path"], item["check_id"]) for item in files["review"]["findings"]}
    assert (".github/workflows/greet.yml", "workflow_injection") in checks
    rows = {(entry["path"], entry["check_id"]): entry["status"] for entry in files["review"]["coverage"]["entries"]
            if entry["required"]}
    assert rows[(".github/workflows/ci.yml", "untrusted_checkout")] == "checked" and files["status"] == "complete"

    git(repository, "add", ".github/workflows/greet.yml")
    assert cli.main([*base, "--staged"]) == 1
    staged = json.loads(capsys.readouterr().out)
    assert [change["path"] for change in staged["changes"]] == [".github/workflows/greet.yml"]
    git(repository, "commit", "-q", "-m", "greet")

    git(repository, "checkout", "-q", "-b", "feature")
    write(repository, "Dockerfile", DOCKERFILE)
    git(repository, "add", "-A")
    git(repository, "commit", "-q", "-m", "image")
    assert cli.main([*base, "--diff", "main...HEAD"]) == 1
    ranged = json.loads(capsys.readouterr().out)
    assert [(item["path"], item["rule_id"], item["severity"]) for item in ranged["review"]["findings"]
            if item["check_id"] == "unverified_download"] == [
        ("Dockerfile", "polaris.docker.unverified_download.pipe_to_shell", "high")]
    assert ranged["status"] == "complete"


def test_pr_plan_comments_on_a_changed_workflow_with_reverified_suggestions(repository, capsys):
    base = git(repository, "rev-parse", "HEAD")
    write(repository, ".github/workflows/greet.yml", RISKY_WORKFLOW)
    git(repository, "add", "-A")
    git(repository, "commit", "-q", "-m", "greet")
    head = git(repository, "rev-parse", "HEAD")
    assert cli.main(["pr", "plan", "--root", str(repository), "--base", base, "--head", head, "--repository",
                     "acme/app", "--pr", "7", "--no-external-analyzers"]) == 0
    plan = ReviewPlan.model_validate_json(capsys.readouterr().out)
    comments = {comment.line: comment for comment in plan.comments}
    assert set(comments) == {10, 14} and {comment.severity for comment in comments.values()} == {"critical"}
    assert comments[10].suggestion == "verified" and comments[14].suggestion == "verified"
    assert '```suggestion\n          echo "Thanks for ${GITHUB_HEAD_REF}"\n```' in comments[10].body
    assert "const title = context.payload.pull_request.title;" in comments[14].body

    review = review_workspace_detailed(repository, revision_range=f"{base}...{head}", runtime=MEMORY)
    findings = [item for item in review.envelope.review.findings if item.suggested_edit is not None]
    assert {result.status for result in verify_edits(review, findings).values()} == {"verified"}
