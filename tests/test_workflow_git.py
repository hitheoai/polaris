"""Only isolated fixture repositories are mutated; the user's worktree/index is never touched."""

from __future__ import annotations

import hashlib
import os
import subprocess

from polaris.review.git import workflow_sources_from_git
from polaris.review.models import WorkflowReviewConfig
from polaris.review.scope import SCOPE_LIMIT_PATH


def fixture_git(root, *args):
    env = {
        "PATH": "/usr/bin:/bin:/opt/homebrew/bin:/usr/local/bin", "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    }
    return subprocess.run(["git", "--no-pager", "-C", str(root), *args],
                          check=True, capture_output=True, env=env).stdout.decode("utf-8")


def test_git_all_languages_deletions_renames_staged_and_unchanged_index(tmp_path):
    fixture_git(tmp_path, "init", "-q", "-b", "main")
    before = 'export function GET() {\r\n  return "before";\r\n}\r\n'
    (tmp_path / "old.ts").write_bytes(before.encode())
    (tmp_path / "gone.py").write_text("pass\n")
    (tmp_path / "notes.md").write_text("old\n")
    fixture_git(tmp_path, "add", ".")
    fixture_git(tmp_path, "commit", "-q", "-m", "fixture baseline")
    fixture_git(tmp_path, "mv", "old.ts", "route.ts")
    (tmp_path / "gone.py").unlink()
    (tmp_path / "notes.md").write_text("new\n")
    (tmp_path / "new.jsx").write_text("export const Component = () => <div />;\n")
    index = tmp_path / ".git" / "index"
    digest = hashlib.sha256(index.read_bytes()).hexdigest()
    sources = {source.path: source for source in workflow_sources_from_git(tmp_path)}
    assert set(sources) == {"route.ts", "gone.py", "notes.md", "new.jsx"}
    assert sources["route.ts"].previous_path == "old.ts"
    assert sources["route.ts"].after == sources["route.ts"].before == before
    assert sources["gone.py"].skip == "deleted" and sources["gone.py"].before == "pass\n"
    assert sources["notes.md"].skip == "unsupported_language"
    assert sources["new.jsx"].after is not None
    assert hashlib.sha256(index.read_bytes()).hexdigest() == digest
    (tmp_path / "route.ts").write_text("export const workingOnly = 1;\n")
    staged = workflow_sources_from_git(tmp_path, staged=True)
    assert len(staged) == 1 and staged[0].after == before and staged[0].previous_path == "old.ts"


def test_unborn_repo_and_global_source_limits(tmp_path):
    fixture_git(tmp_path, "init", "-q", "-b", "main")
    for name in ("a.ts", "b.ts", "c.ts"):
        (tmp_path / name).write_text("export const value = 1;\n")
    fixture_git(tmp_path, "add", "a.ts")
    all_sources = workflow_sources_from_git(tmp_path)
    assert {source.path for source in all_sources} == {"a.ts", "b.ts", "c.ts"}
    assert all(source.before is None for source in all_sources)
    capped = workflow_sources_from_git(tmp_path, max_files=1)
    assert len(capped) == 2 and capped[-1].path == SCOPE_LIMIT_PATH and capped[-1].skip == "file_limit"
    limited = workflow_sources_from_git(tmp_path, max_total_bytes=24)
    assert limited[0].after is not None and any(source.skip == "total_source_limit" for source in limited[1:])
    excluded = workflow_sources_from_git(tmp_path, config=WorkflowReviewConfig(exclude=["a.ts"]))
    assert excluded[0].skip == "excluded"


def test_three_dot_before_uses_merge_base_not_advanced_left_branch(tmp_path):
    fixture_git(tmp_path, "init", "-q", "-b", "main")
    base = "export const value = 1;\n"
    (tmp_path / "route.ts").write_text(base)
    fixture_git(tmp_path, "add", ".")
    fixture_git(tmp_path, "commit", "-q", "-m", "fixture base")
    fixture_git(tmp_path, "branch", "feature")
    (tmp_path / "route.ts").write_text("export const value = 2;\n")
    fixture_git(tmp_path, "add", ".")
    fixture_git(tmp_path, "commit", "-q", "-m", "fixture main change")
    fixture_git(tmp_path, "checkout", "-q", "feature")
    (tmp_path / "route.ts").write_text("export const value = 3;\n")
    fixture_git(tmp_path, "add", ".")
    fixture_git(tmp_path, "commit", "-q", "-m", "fixture feature change")
    sources = workflow_sources_from_git(tmp_path, revision_range="main...feature")
    assert len(sources) == 1 and sources[0].before == base
    assert sources[0].after == "export const value = 3;\n"


def test_git_disables_clean_process_textconv_fsmonitor_and_external_helpers(tmp_path):
    fixture_git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "app.ts").write_text("export const value = 1;\n")
    fixture_git(tmp_path, "add", ".")
    fixture_git(tmp_path, "commit", "-q", "-m", "fixture baseline")
    marker = tmp_path / "helper-must-not-run"
    # Harmless fixture canary, configured after seeding. No real repository code is used.
    helper = f"/usr/bin/touch {marker}"
    for key in ("filter.fixture.clean", "filter.fixture.process", "diff.fixture.textconv",
                "core.fsmonitor", "diff.external"):
        fixture_git(tmp_path, "config", key, helper)
    fixture_git(tmp_path, "config", "filter.fixture.required", "true")
    (tmp_path / ".gitattributes").write_text("*.ts filter=fixture diff=fixture\n")
    (tmp_path / "app.ts").write_text("export const value = 2;\n")
    sources = workflow_sources_from_git(tmp_path)
    assert next(source for source in sources if source.path == "app.ts").after == "export const value = 2;\n"
    assert not marker.exists()
