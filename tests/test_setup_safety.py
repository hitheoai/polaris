"""Safe setup boundaries exercised only against disposable files and fake HOME."""

import os
from pathlib import Path

import pytest
from integration_helpers import isolated_home_fixture, repository_fixture  # noqa: F401

from polaris.integrations import _safe, setup
from polaris.integrations._safe import IntegrationProblem


@pytest.mark.parametrize("mutation", ["content", "mode", "replacement"])
def test_stale_plan_does_not_overwrite_concurrent_changes(repository, mutation):
    path = repository / ".mcp.json"
    path.write_text("{}\n")
    plan = setup.plan_project("warp", repository)
    if mutation == "content":
        path.write_text('{"user": "new"}\n')
    elif mutation == "mode":
        path.chmod(0o600)
    else:
        replacement = repository / "replacement"
        replacement.write_bytes(path.read_bytes())
        os.replace(replacement, path)
    before = path.read_bytes(), path.stat().st_mode
    with pytest.raises(setup.SetupProblem, match="changed after planning"):
        setup.apply_plan(plan)
    assert (path.read_bytes(), path.stat().st_mode) == before
    assert not (repository / "AGENTS.md").exists()


@pytest.mark.parametrize("existing", [False, True])
def test_partial_application_rolls_back_only_its_writes(repository, isolated_home, monkeypatch, existing):
    path = repository / ".mcp.json"
    if existing:
        path.write_text('{"untouched": "original"}\n')
        path.chmod(0o640)
    plan = setup.plan_project("warp", repository)
    original_write = setup._write

    def failing_write(change):
        if change.path.name == "AGENTS.md":
            raise OSError("fixture-private-error")
        return original_write(change)

    monkeypatch.setattr(setup, "_write", failing_write)
    with pytest.raises(setup.SetupProblem, match="rolled back") as problem:
        setup.apply_plan(plan)
    assert "fixture-private" not in str(problem.value)
    assert not (repository / "AGENTS.md").exists()
    if existing:
        assert path.read_text() == '{"untouched": "original"}\n'
        assert path.stat().st_mode & 0o777 == 0o640
        backups = list((isolated_home / ".polaris" / "backups").rglob("*mcp.json"))
        assert len(backups) == 1 and backups[0].read_bytes() == path.read_bytes()
        assert backups[0].stat().st_mode & 0o777 == 0o600
    else:
        assert not path.exists()


def test_rollback_never_reverts_a_file_changed_by_another_writer(repository, monkeypatch):
    path = repository / ".mcp.json"
    original_write = setup._write

    def concurrent_write(change):
        if change.path.name == "AGENTS.md":
            path.write_text('{"concurrent": "preserve"}\n')
            raise IntegrationProblem("fixture-private-error")
        return original_write(change)

    monkeypatch.setattr(setup, "_write", concurrent_write)
    with pytest.raises(setup.SetupProblem, match="Concurrently changed"):
        setup.configure_project("warp", repository)
    assert path.read_text() == '{"concurrent": "preserve"}\n'
    assert not (repository / "AGENTS.md").exists()


def test_plan_refuses_a_replaced_directory_even_with_identical_file_bytes(repository):
    folder = repository / ".cursor"
    folder.mkdir()
    (folder / "mcp.json").write_text("{}\n")
    plan = setup.plan_project("cursor", repository)
    folder.rename(repository / "old-cursor")
    folder.mkdir()
    (folder / "mcp.json").write_text("{}\n")
    with pytest.raises(setup.SetupProblem, match="directory changed"):
        setup.apply_plan(plan)
    assert (folder / "mcp.json").read_text() == "{}\n"
    assert not (folder / "rules").exists()


def test_atomic_write_rechecks_content_after_staging(repository, monkeypatch):
    path = repository / "destination"
    path.write_bytes(b"before")
    snapshot = _safe.read_snapshot(path)
    fsync = os.fsync

    def concurrent_change(descriptor):
        fsync(descriptor)
        path.write_bytes(b"concurrent")

    monkeypatch.setattr(os, "fsync", concurrent_change)
    with pytest.raises(IntegrationProblem, match="changed after planning"):
        _safe.atomic_write(path, b"after", expected=b"before", expected_snapshot=snapshot,
                           check_expected=True)
    assert path.read_bytes() == b"concurrent"
    assert not list(repository.glob(".polaris-*.tmp"))


def test_atomic_write_does_not_follow_a_concurrent_parent_symlink(repository, tmp_path, monkeypatch):
    folder = repository / "configuration"
    folder.mkdir()
    path = folder / "destination"
    path.write_bytes(b"before")
    outside = tmp_path / "outside"
    outside.mkdir()
    moved = repository / "old-configuration"
    fsync = os.fsync

    def replace_parent(descriptor):
        fsync(descriptor)
        folder.rename(moved)
        folder.symlink_to(outside, target_is_directory=True)

    monkeypatch.setattr(os, "fsync", replace_parent)
    with pytest.raises(IntegrationProblem, match="symbolic link"):
        _safe.atomic_write(path, b"after", expected=b"before", check_expected=True)
    assert (moved / "destination").read_bytes() == b"before"
    assert list(outside.iterdir()) == []
    assert not list(moved.glob(".polaris-*.tmp"))


@pytest.mark.parametrize("target,path", [
    ("warp", ".mcp.json"),
    ("codex", ".codex"),
    ("codex", "AGENTS.override.md"),
    ("claude-code", ".claude"),
])
def test_guided_setup_rejects_symlinks_without_partial_writes(repository, tmp_path, target, path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (repository / path).symlink_to(outside, target_is_directory=True)
    with pytest.raises((setup.SetupProblem, IntegrationProblem)):
        setup.configure_project(target, repository)
    assert list(outside.iterdir()) == []
    config = repository / setup.EDITOR_SETUP[target].project_config
    assert not config.exists() or config.is_symlink()
    assert not (repository / "AGENTS.md").exists()


def test_guided_setup_refuses_home_filesystem_and_symlink_roots(repository, isolated_home, tmp_path):
    alias = tmp_path / "alias"
    alias.symlink_to(repository, target_is_directory=True)
    for root in (Path("/"), isolated_home, isolated_home.parent, alias):
        with pytest.raises((setup.SetupProblem, IntegrationProblem)):
            setup.configure_project("warp", root)
    assert not (repository / ".mcp.json").exists()


def test_setup_lock_refuses_simultaneous_writers_and_symlinks(repository, isolated_home, tmp_path):
    home = isolated_home / ".polaris"
    plan = setup.plan_project("warp", repository)
    with setup._setup_lock(home):
        with pytest.raises(IntegrationProblem, match="in progress"):
            setup.apply_plan(plan)
    lock = home / "setup.lock"
    lock.unlink()
    external = tmp_path / "external-lock"
    external.write_bytes(b"untouched")
    lock.symlink_to(external)
    with pytest.raises(IntegrationProblem, match="symbolic link"):
        setup.apply_plan(plan)
    assert external.read_bytes() == b"untouched"
    assert not (repository / ".mcp.json").exists()


def test_guided_setup_preserves_a_different_named_server_instead_of_forcing_it(repository):
    path = repository / ".mcp.json"
    before = '{"mcpServers": {"polaris": {"command": "other-program", "args": ["serve"]}}}\n'
    path.write_text(before)
    with pytest.raises(setup.Refused):
        setup.configure_project("warp", repository)
    assert path.read_text() == before and not (repository / "AGENTS.md").exists()
