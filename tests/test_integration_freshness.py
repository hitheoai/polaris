import os

import pytest
from integration_helpers import git, isolated_home_fixture, repository_fixture  # noqa: F401

from polaris.integrations._safe import IntegrationProblem, offline_environment
from polaris.integrations.freshness import (
    SnapshotLimits,
    capture_snapshot,
    git_bytes,
    is_fresh,
    read_receipt,
    repository_identity,
    state_directory,
    write_receipt,
)


def test_content_not_timestamps_binds_every_language_and_untracked_context(repository):
    before = capture_snapshot(repository)
    assert before.complete and is_fresh(before, capture_snapshot(repository))
    path = repository / "main.py"
    info = path.stat()
    path.write_text("def add(a, b):\n    return a - b\n")
    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
    assert not is_fresh(before, capture_snapshot(repository))
    prior = capture_snapshot(repository)
    (repository / "route.ts").write_text("export const allowed = false;\n")
    assert not is_fresh(prior, capture_snapshot(repository))
    prior = capture_snapshot(repository)
    (repository / "arbitrary-context.txt").write_text("non-code context also matters\n")
    assert not is_fresh(prior, capture_snapshot(repository))


@pytest.mark.parametrize("name", ["package-lock.json", "pyproject.toml", ".polaris.toml", ".env", "AGENTS.md"])
def test_dependency_policy_and_ignored_root_config_changes_invalidate(repository, name):
    (repository / ".gitignore").write_text(".env\n")
    before = capture_snapshot(repository)
    (repository / name).write_text("fixture-private-context\n")
    after = capture_snapshot(repository)
    assert not is_fresh(before, after)
    assert "fixture-private-context" not in str(after.to_dict())


def test_policy_matrix_analyzer_and_model_versions_are_part_of_identity(repository):
    variants = [
        {"policy": ["require_guard"]},
        {"check_matrix": {"python": ["sql_injection"], "typescript": []}},
        {"analyzer_versions": {"python": "v2"}},
        {"model_versions": {"model": "experimental-v2", "digest": "fixture-digest"}},
    ]
    base = capture_snapshot(repository)
    for options in variants:
        current = capture_snapshot(repository, **options)
        assert not is_fresh(base, current)
        assert is_fresh(current, capture_snapshot(repository, **options))


def test_staging_and_branch_revision_identity_invalidate_without_working_tree_edits(repository):
    (repository / "main.py").write_text("def add(a, b):\n    return a - b\n")
    unstaged = capture_snapshot(repository)
    git(repository, "add", "main.py")
    staged = capture_snapshot(repository)
    assert unstaged.index_digest != staged.index_digest and not is_fresh(unstaged, staged)
    git(repository, "commit", "-qm", "fixture change")
    assert not is_fresh(staged, capture_snapshot(repository))


def test_local_state_never_creates_source_dirtiness_or_freshness_loops(repository):
    before = capture_snapshot(repository)
    status = git(repository, "status", "--porcelain")
    path = write_receipt(before, {"status": "complete", "tests_status": "not_run"})
    assert path.is_relative_to(repository / ".git")
    assert git(repository, "status", "--porcelain") == status
    after = capture_snapshot(repository)
    receipt = read_receipt(repository)
    assert receipt["trust"] == "mutable_local_hint_not_ci_evidence"
    assert is_fresh(before, after) and is_fresh(receipt, after)
    assert path.stat().st_mode & 0o777 == 0o600


def test_linked_worktrees_have_distinct_identity_and_state(repository, tmp_path):
    linked = tmp_path / "linked"
    git(repository, "worktree", "add", "-qb", "fixture-branch", str(linked))
    left, right = capture_snapshot(repository), capture_snapshot(linked)
    assert left.repository_id == right.repository_id and left.worktree_id != right.worktree_id
    assert not is_fresh(left, right)
    assert state_directory(repository) != state_directory(linked)
    write_receipt(right, {"status": "complete"})
    assert is_fresh(right, capture_snapshot(linked))
    assert read_receipt(repository) is None
    assert git(repository, "status", "--porcelain") == ""
    assert git(linked, "status", "--porcelain") == ""


def test_symlink_files_ancestors_and_roots_cannot_supply_reviewed_content(repository, tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    (external / "value.txt").write_text("fixture-external-data")
    (repository / "link").symlink_to(external, target_is_directory=True)
    snapshot = capture_snapshot(repository, extra_paths=["link/value.txt"])
    assert not snapshot.complete and snapshot.omissions
    assert "fixture-external-data" not in str(snapshot.to_dict())
    assert not is_fresh(snapshot, snapshot)
    alias = tmp_path / "alias"
    alias.symlink_to(repository, target_is_directory=True)
    with pytest.raises(IntegrationProblem, match="symbolic link"):
        capture_snapshot(alias)


def test_state_symlink_is_never_followed(repository, tmp_path):
    external = tmp_path / "outside-state"
    external.mkdir()
    (repository / ".git" / "polaris-agent").symlink_to(external, target_is_directory=True)
    with pytest.raises(IntegrationProblem, match="symbolic link"):
        write_receipt(capture_snapshot(repository), {"status": "complete"})
    assert not list(external.iterdir())


def test_bounds_are_explicit_not_silent_truncation(repository):
    limited = capture_snapshot(repository, limits=SnapshotLimits(max_files=1))
    assert not limited.complete and any("file_count_limit" in item.reason for item in limited.omissions)
    (repository / "large.txt").write_text("x" * 2000)
    limited = capture_snapshot(repository, limits=SnapshotLimits(max_file_bytes=1000))
    assert not limited.complete and any(item.reason == "file_byte_limit" for item in limited.omissions)
    assert "Git-ignored" in limited.omitted_scope[0]
    with pytest.raises(IntegrationProblem):
        capture_snapshot(repository, extra_paths=["../outside"])


def test_untracked_newline_names_are_not_split_and_deletions_change_snapshot(repository):
    name = "notes\nfixture.txt"
    (repository / name).write_text("fixture")
    before = capture_snapshot(repository)
    assert name in {item.path for item in before.files}
    (repository / name).unlink()
    assert not is_fresh(before, capture_snapshot(repository))


def test_git_overrides_and_fsmonitor_cannot_execute_project_commands(repository, monkeypatch):
    trap = repository / "trap.sh"
    marker = repository / "executed"
    trap.write_text(f"#!/bin/sh\nprintf trap > '{marker}'\n")
    trap.chmod(0o755)
    git(repository, "config", "core.fsmonitor", str(trap))
    monkeypatch.setenv("GIT_DIR", "/not-the-reviewed-repository")
    assert capture_snapshot(repository).complete
    assert repository_identity(repository).root == repository
    assert not marker.exists()


def test_git_metadata_symlinks_and_configured_worktree_redirects_are_rejected(repository, tmp_path):
    (repository / ".git").rename(repository / ".git-actual")
    (repository / ".git").symlink_to(repository / ".git-actual", target_is_directory=True)
    with pytest.raises(IntegrationProblem, match="symbolic link"):
        capture_snapshot(repository)
    (repository / ".git").unlink()
    (repository / ".git-actual").rename(repository / ".git")
    outside = (tmp_path / "other-worktree").resolve()
    outside.mkdir()
    git(repository, "config", "core.worktree", str(outside))
    with pytest.raises(IntegrationProblem, match="different worktree"):
        capture_snapshot(repository)


def test_offline_git_denies_transport_even_when_repository_config_allows_it(repository, isolated_home):
    env = offline_environment(isolated_home)
    assert env["GIT_NO_LAZY_FETCH"] == "1" and env["GIT_ALLOW_PROTOCOL"] == ""
    git(repository, "config", "protocol.file.allow", "always")
    # Synthetic local endpoint only: the environment must reject transport before reading it.
    with pytest.raises(IntegrationProblem, match="could not read"):
        git_bytes(repository, "ls-remote", repository.as_uri())
